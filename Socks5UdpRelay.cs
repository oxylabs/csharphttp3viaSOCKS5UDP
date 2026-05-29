using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using static Http3Socks5Demo.Socks5Constants;

namespace Http3Socks5Demo;

/// <summary>
/// In-process loopback UDP shim that re-frames datagrams between an HTTP/3
/// (QUIC) client and a SOCKS5 UDP relay endpoint.
///
/// Layout:
///   QUIC client &lt;--UDP--&gt; 127.0.0.1:LocalPort  &lt;--SOCKS5 UDP--&gt; proxy relay
///
/// The QUIC client (HttpClient HTTP/3) sees a normal UDP server on loopback.
/// Every datagram it sends is prepended with the SOCKS5 UDP request header
/// (RFC 1928 §7) and forwarded to the relay; every reply is stripped of the
/// header and forwarded back to the QUIC client's source endpoint.
/// </summary>
internal sealed class Socks5UdpRelay : IAsyncDisposable
{
    private readonly UdpClient _local;
    private readonly UdpClient _remote;
    private readonly CancellationTokenSource _cts = new();
    private readonly byte[] _headerTemplate;

    private Task? _clientToRelayPump;
    private Task? _relayToClientPump;

    private IPEndPoint? _quicSourceEndPoint;

    private Socks5UdpRelay(UdpClient local, UdpClient remote, string targetHost, ushort targetPort)
    {
        _local = local;
        _remote = remote;
        _headerTemplate = BuildHeader(targetHost, targetPort);
    }

    /// <summary>Loopback port the QUIC client should send to.</summary>
    public int LocalPort => ((IPEndPoint)_local.Client.LocalEndPoint!).Port;

    /// <summary>
    /// Starts the relay. Binds a UDP socket on 127.0.0.1, connects another UDP
    /// socket to the SOCKS5 relay endpoint, and kicks off both pump tasks.
    /// </summary>
    public static Socks5UdpRelay Start(IPEndPoint relayEndPoint, string targetHost, ushort targetPort)
    {
        var local = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        UdpClient? remote = null;
        try
        {
            remote = new UdpClient(relayEndPoint.AddressFamily);
            remote.Connect(relayEndPoint);

            var relay = new Socks5UdpRelay(local, remote, targetHost, targetPort);
            relay._clientToRelayPump = Task.Run(relay.PumpClientToRelayAsync);
            relay._relayToClientPump = Task.Run(relay.PumpRelayToClientAsync);
            return relay;
        }
        catch
        {
            local.Dispose();
            remote?.Dispose();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();

        await SafeAwait(_clientToRelayPump).ConfigureAwait(false);
        await SafeAwait(_relayToClientPump).ConfigureAwait(false);

        _local.Dispose();
        _remote.Dispose();
        _cts.Dispose();
    }

    private static async Task SafeAwait(Task? task)
    {
        if (task is null) return;
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (SocketException) { }
    }

    private async Task PumpClientToRelayAsync()
    {
        CancellationToken ct = _cts.Token;
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult received;
            try
            {
                received = await _local.ReceiveAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { return; }

            Volatile.Write(ref _quicSourceEndPoint, received.RemoteEndPoint);

            byte[] payload = received.Buffer;
            int datagramLength = _headerTemplate.Length + payload.Length;
            byte[] datagram = ArrayPool<byte>.Shared.Rent(datagramLength);
            try
            {
                _headerTemplate.CopyTo(datagram.AsSpan());
                payload.CopyTo(datagram.AsSpan(_headerTemplate.Length));

                await _remote.SendAsync(datagram.AsMemory(0, datagramLength), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { }
            finally
            {
                ArrayPool<byte>.Shared.Return(datagram);
            }
        }
    }

    private async Task PumpRelayToClientAsync()
    {
        CancellationToken ct = _cts.Token;
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult received;
            try
            {
                received = await _remote.ReceiveAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { return; }

            if (!TryStripHeader(received.Buffer, out ReadOnlyMemory<byte> payload))
            {
                continue;
            }

            IPEndPoint? destination = Volatile.Read(ref _quicSourceEndPoint);
            if (destination is null)
            {
                continue;
            }

            try
            {
                await _local.SendAsync(payload, destination, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { }
        }
    }

    /// <summary>
    /// Builds the constant prefix for every outbound datagram:
    /// <c>RSV(2) || FRAG(1) || ATYP(1) || DST.ADDR || DST.PORT(2)</c> (RFC 1928 §7).
    /// </summary>
    private static byte[] BuildHeader(string targetHost, ushort targetPort)
    {
        if (IPAddress.TryParse(targetHost, out IPAddress? ip))
        {
            byte atyp = ip.AddressFamily == AddressFamily.InterNetworkV6
                ? AddressTypeIPv6
                : AddressTypeIPv4;
            byte[] addrBytes = ip.GetAddressBytes();
            return BuildHeaderCore(atyp, addrBytes, addressLengthPrefix: false, targetPort);
        }

        byte[] nameBytes = Encoding.ASCII.GetBytes(targetHost);
        if (nameBytes.Length > 255)
        {
            throw new ArgumentException("Target hostname must be at most 255 ASCII bytes for SOCKS5 ATYP=DOMAINNAME.");
        }
        return BuildHeaderCore(AddressTypeDomain, nameBytes, addressLengthPrefix: true, targetPort);
    }

    private static byte[] BuildHeaderCore(byte atyp, ReadOnlySpan<byte> address, bool addressLengthPrefix, ushort port)
    {
        int prefix = addressLengthPrefix ? 1 : 0;
        var header = new byte[4 + prefix + address.Length + 2];
        Span<byte> span = header.AsSpan();
        // RSV(2) and FRAG(1) are already zero from the array allocation.
        span[3] = atyp;
        if (addressLengthPrefix)
        {
            span[4] = (byte)address.Length;
        }
        address.CopyTo(span[(4 + prefix)..]);
        BinaryPrimitives.WriteUInt16BigEndian(span[^2..], port);
        return header;
    }

    private static bool TryStripHeader(byte[] datagram, out ReadOnlyMemory<byte> payload)
    {
        payload = default;
        if (datagram.Length < 4) return false;
        if (datagram[2] != 0x00)
        {
            return false;
        }
        int addrLen;
        switch (datagram[3])
        {
            case AddressTypeIPv4:
                addrLen = 4;
                break;
            case AddressTypeIPv6:
                addrLen = 16;
                break;
            case AddressTypeDomain:
                if (datagram.Length < 5) return false;
                addrLen = 1 + datagram[4];
                break;
            default:
                return false;
        }

        int headerLen = 4 + addrLen + 2;
        if (datagram.Length < headerLen) return false;
        payload = datagram.AsMemory(headerLen);
        return true;
    }
}
