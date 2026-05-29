using System.Net;
using System.Net.Sockets;
using System.Text;
using static Http3Socks5Demo.Socks5Constants;

namespace Http3Socks5Demo;

/// <summary>
/// Minimal RFC 1928 SOCKS5 client that negotiates a UDP ASSOCIATE.
///
/// The TCP "control" connection MUST stay open for the entire lifetime of
/// the UDP relay; closing it instructs the proxy to tear the association down.
/// Disposing this object closes that control connection.
/// </summary>
internal sealed class Socks5UdpClient : IAsyncDisposable
{
    private readonly TcpClient _control;

    private Socks5UdpClient(TcpClient control, IPEndPoint relayEndPoint)
    {
        _control = control;
        RelayEndPoint = relayEndPoint;
    }

    /// <summary>
    /// UDP relay endpoint returned by the proxy. Datagrams wrapped in the SOCKS5
    /// UDP request header (RFC 1928 §7) must be sent to this endpoint.
    /// </summary>
    public IPEndPoint RelayEndPoint { get; }

    /// <summary>
    /// Connects to the proxy, performs the greeting, optional user/password auth
    /// (RFC 1929), and a UDP ASSOCIATE request. Returns a client that owns the
    /// open TCP control connection.
    /// </summary>
    public static async Task<Socks5UdpClient> ConnectAsync(
        string proxyHost,
        int proxyPort,
        string? username,
        string? password,
        CancellationToken cancellationToken = default)
    {
        var tcp = new TcpClient();
        try
        {
            await tcp.ConnectAsync(proxyHost, proxyPort, cancellationToken).ConfigureAwait(false);

            NetworkStream stream = tcp.GetStream();
            await GreetAsync(stream, !string.IsNullOrEmpty(username), cancellationToken).ConfigureAwait(false);

            var method = await ReadGreetingReplyAsync(stream, cancellationToken).ConfigureAwait(false);
            switch (method)
            {
                case AuthNone:
                    break;
                case AuthUserPass:
                    await AuthenticateAsync(stream, username ?? string.Empty, password ?? string.Empty, cancellationToken).ConfigureAwait(false);
                    break;
                case AuthNoneAcceptable:
                    throw new IOException("SOCKS5 proxy rejected all offered authentication methods.");
                default:
                    throw new IOException($"SOCKS5 proxy selected unsupported authentication method 0x{method:X2}.");
            }

            IPEndPoint relayEndPoint = await RequestUdpAssociateAsync(stream, tcp, cancellationToken).ConfigureAwait(false);
            return new Socks5UdpClient(tcp, relayEndPoint);
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    public ValueTask DisposeAsync()
    {
        _control.Dispose();
        return ValueTask.CompletedTask;
    }

    private static async Task GreetAsync(NetworkStream stream, bool offerUserPass, CancellationToken ct)
    {
        // VER=5, NMETHODS, METHODS[...]
        byte[] greeting = offerUserPass
            ? [SocksVersion, 0x02, AuthNone, AuthUserPass]
            : [SocksVersion, 0x01, AuthNone];
        await stream.WriteAsync(greeting, ct).ConfigureAwait(false);
    }

    private static async Task<byte> ReadGreetingReplyAsync(NetworkStream stream, CancellationToken ct)
    {
        var reply = new byte[2];
        await stream.ReadExactlyAsync(reply, ct).ConfigureAwait(false);
        if (reply[0] != SocksVersion)
        {
            throw new IOException($"Unexpected SOCKS version in greeting reply: 0x{reply[0]:X2}.");
        }
        return reply[1];
    }

    private static async Task AuthenticateAsync(NetworkStream stream, string user, string pass, CancellationToken ct)
    {
        var userBytes = Encoding.UTF8.GetBytes(user);
        var passBytes = Encoding.UTF8.GetBytes(pass);
        if (userBytes.Length > 255 || passBytes.Length > 255)
        {
            throw new ArgumentException("SOCKS5 username/password must each be at most 255 bytes.");
        }

        // RFC 1929: VER=1, ULEN, UNAME, PLEN, PASSWD
        var request = new byte[3 + userBytes.Length + passBytes.Length];
        request[0] = AuthSubVersion;
        request[1] = (byte)userBytes.Length;
        Buffer.BlockCopy(userBytes, 0, request, 2, userBytes.Length);
        request[2 + userBytes.Length] = (byte)passBytes.Length;
        Buffer.BlockCopy(passBytes, 0, request, 3 + userBytes.Length, passBytes.Length);

        await stream.WriteAsync(request, ct).ConfigureAwait(false);

        var reply = new byte[2];
        await stream.ReadExactlyAsync(reply, ct).ConfigureAwait(false);
        if (reply[0] != AuthSubVersion)
        {
            throw new IOException($"Unexpected SOCKS5 auth subnegotiation version: 0x{reply[0]:X2}.");
        }
        if (reply[1] != 0x00)
        {
            throw new IOException($"SOCKS5 user/password authentication failed (status=0x{reply[1]:X2}).");
        }
    }

    private static async Task<IPEndPoint> RequestUdpAssociateAsync(NetworkStream stream, TcpClient tcp, CancellationToken ct)
    {
        // VER=5, CMD=UDP_ASSOCIATE, RSV=0, ATYP=IPv4, DST.ADDR=0.0.0.0, DST.PORT=0
        var request = new byte[] { SocksVersion, CommandUdpAssociate, 0x00, AddressTypeIPv4, 0, 0, 0, 0, 0, 0 };
        await stream.WriteAsync(request, ct).ConfigureAwait(false);

        var header = new byte[4];
        await stream.ReadExactlyAsync(header, ct).ConfigureAwait(false);
        if (header[0] != SocksVersion)
        {
            throw new IOException($"Unexpected SOCKS version in UDP ASSOCIATE reply: 0x{header[0]:X2}.");
        }
        if (header[1] != ReplySucceeded)
        {
            throw new IOException($"SOCKS5 UDP ASSOCIATE failed (REP=0x{header[1]:X2}).");
        }

        IPAddress bindAddress;
        switch (header[3])
        {
            case AddressTypeIPv4:
            {
                var addr = new byte[4];
                await stream.ReadExactlyAsync(addr, ct).ConfigureAwait(false);
                bindAddress = new IPAddress(addr);
                break;
            }
            case AddressTypeIPv6:
            {
                var addr = new byte[16];
                await stream.ReadExactlyAsync(addr, ct).ConfigureAwait(false);
                bindAddress = new IPAddress(addr);
                break;
            }
            case AddressTypeDomain:
            {
                var lenBuf = new byte[1];
                await stream.ReadExactlyAsync(lenBuf, ct).ConfigureAwait(false);
                var name = new byte[lenBuf[0]];
                await stream.ReadExactlyAsync(name, ct).ConfigureAwait(false);
                var host = Encoding.ASCII.GetString(name);
                bindAddress = await ResolveRelayHostAsync(host, tcp, ct).ConfigureAwait(false);
                break;
            }
            default:
                throw new IOException($"Unknown ATYP in UDP ASSOCIATE reply: 0x{header[3]:X2}.");
        }

        var portBuf = new byte[2];
        await stream.ReadExactlyAsync(portBuf, ct).ConfigureAwait(false);
        int port = (portBuf[0] << 8) | portBuf[1];

        // Per RFC 1928 §6, if BND.ADDR is 0.0.0.0 the relay is reachable on the
        // same host as the TCP control connection.
        if (bindAddress.Equals(IPAddress.Any) || bindAddress.Equals(IPAddress.IPv6Any))
        {
            if (tcp.Client.RemoteEndPoint is IPEndPoint remote)
            {
                bindAddress = remote.Address;
            }
        }

        return new IPEndPoint(bindAddress, port);
    }

    /// <summary>
    /// Resolves <paramref name="host"/>, preferring an address in the same
    /// family as the proxy's TCP control connection. The SOCKS5 UDP relay is
    /// expected to be reachable on the same host as the proxy itself, so the
    /// IP families should match.
    /// </summary>
    private static async Task<IPAddress> ResolveRelayHostAsync(string host, TcpClient tcp, CancellationToken ct)
    {
        IPAddress[] addresses = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        if (addresses.Length == 0)
        {
            throw new IOException($"Could not resolve SOCKS5 UDP relay host '{host}'.");
        }

        if (tcp.Client.RemoteEndPoint is IPEndPoint remote)
        {
            foreach (IPAddress addr in addresses)
            {
                if (addr.AddressFamily == remote.AddressFamily)
                {
                    return addr;
                }
            }
        }
        return addresses[0];
    }
}
