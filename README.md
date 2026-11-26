# HTTP/3 via SOCKS5 UDP — C# (.NET 8) Example

<a href="https://oxylabs.io/?utm_source=github&utm_medium=referral&utm_content=csharphttp3viasocks5udp&utm_campaign=banner&groupid=877"><img src="https://img.shields.io/badge/🚀_Get_Started-FF6B35?style=for-the-badge" alt="Get started"></a>
<a href="https://developers.oxylabs.io"><img src="https://img.shields.io/badge/📚_Documentation-4A90E2?style=for-the-badge" alt="Documentation"></a>
<a href="https://dashboard.oxylabs.io"><img src="https://img.shields.io/badge/📊_Dashboard-2EA44F?style=for-the-badge" alt="Dashboard"></a>
<a href="https://discord.gg/Pds3gBmKMH"><img src="https://img.shields.io/badge/💬_Discord-5865F2?style=for-the-badge" alt="Discord"></a>
<a href="https://www.youtube.com/@oxylabs"><img src="https://img.shields.io/badge/▶️_YouTube-FF0000?style=for-the-badge" alt="YouTube"></a>

Performs an HTTP/3 request through a SOCKS5 **UDP** proxy.

HTTP/3 runs on UDP (QUIC), which requires the proxy to support SOCKS5 `UDP ASSOCIATE` (RFC 1928 §7) — a feature most HTTP client libraries do not expose. This sample bridges the gap by:

- Negotiating SOCKS5 `UDP ASSOCIATE` (with optional user/password auth, RFC 1929).
- Running an in-process loopback UDP shim that re-frames every QUIC datagram with the SOCKS5 UDP header and forwards it to the proxy's UDP relay (and vice versa).
- Pointing the .NET `HttpClient` HTTP/3 stack at the loopback shim while keeping TLS SNI and the HTTP `:authority` set to the real target.

## Prerequisites

- .NET 8 SDK
- `MsQuic` runtime (required for HTTP/3 in `HttpClient`):
  - **Windows / Linux:** shipped with the .NET 8 runtime — no action needed in most cases.
  - **macOS:** `brew install msquic`

## Build

```bash
dotnet build -c Release
```

This produces `bin/Release/net8.0/http3viasocks5udp` (or `.exe` on Windows).

For a self-contained binary:

```bash
dotnet publish -c Release -r osx-arm64 --self-contained -p:PublishSingleFile=true
# or: linux-x64, win-x64, osx-x64
```

## Usage

```
  -body string
        optional request body
  -h string
        proxy host with port, i.e. host:port (default "socks.pr.oxylabs.io:7777")
  -p string
        proxy password
  -t string
        target host (default "echo-udp.oxylabs.io")
  -u string
        proxy username
```

For example:

```bash
dotnet run -- -h socks.pr.oxylabs.io:7777 -u myproxyusername -p myproxypassword -t echo-udp.oxylabs.io -body "Hello HTTP3"
```

Or the built binary:

```bash
./bin/Release/net8.0/http3viasocks5udp \
  -h socks.pr.oxylabs.io:7777 \
  -u myproxyusername \
  -p myproxypassword \
  -t echo-udp.oxylabs.io \
  -body "Hello HTTP3"
```

## How it works

```
+---------------------+   QUIC over UDP   +-----------------------+   SOCKS5 UDP    +-------------+
| HttpClient HTTP/3   | <---------------> | Loopback shim         | <-------------> | SOCKS5 UDP  |
| (MsQuic, dial       |  127.0.0.1:NNNN   | (Socks5UdpRelay)      |  BND.ADDR:PORT  | relay       |
|  127.0.0.1:NNNN)    |                   | wraps/unwraps SOCKS5  |                 |             |
+---------------------+                   +-----------------------+                 +-------------+
                                                                                            |
                                                                                            v
                                                                                  +-------------------+
                                                                                  | echo-udp.oxylabs  |
                                                                                  | .io:443 (HTTP/3)  |
                                                                                  +-------------------+

(separate TCP control connection to the SOCKS5 proxy is held open the whole time)
```

Key tricks:

- `Socks5UdpClient` opens the **TCP** control connection, runs the greeting + optional `USER/PASS` auth, then issues `UDP ASSOCIATE`. The control connection is kept open for the lifetime of the request — closing it tells the proxy to tear down the UDP relay.
- `Socks5UdpRelay` binds a UDP socket on `127.0.0.1`, plus a second UDP socket connected to the proxy's relay endpoint. Two `Task` pumps run concurrently:
  - **client → relay:** prepend the RFC 1928 §7 header (`ATYP=DOMAINNAME`, the real target host + port) to each datagram from `HttpClient`/MsQuic.
  - **relay → client:** strip the header off each reply and forward the QUIC payload back to MsQuic's source port.
- `Http3Socks5Runner` issues the request to `https://127.0.0.1:<localPort>/` so MsQuic dials the loopback shim, but pre-sets `SocketsHttpHandler.SslOptions.TargetHost = "<real target>"` so the TLS SNI still advertises the real hostname, and overrides `request.Headers.Host` so the origin sees the real `:authority`. `RemoteCertificateValidationCallback` returns `true` (mirroring the Go example's `InsecureSkipVerify`).

## Files

| File | Purpose |
| --- | --- |
| [`Program.cs`](Program.cs) | CLI flag parsing and lifecycle orchestration. |
| [`Socks5UdpClient.cs`](Socks5UdpClient.cs) | SOCKS5 greeting, RFC 1929 auth, and `UDP ASSOCIATE`. |
| [`Socks5UdpRelay.cs`](Socks5UdpRelay.cs) | Loopback UDP shim with SOCKS5 header wrap/unwrap. |
| [`Http3Socks5Runner.cs`](Http3Socks5Runner.cs) | `HttpClient` HTTP/3 wiring with SNI + cert overrides. |

## Caveats

- **UDP target only:** the SOCKS5 `UDP ASSOCIATE` association only forwards UDP datagrams. The target must speak HTTP/3 (i.e. UDP/443). It cannot be used to proxy HTTP/1.1 or HTTP/2 traffic.
- **One request per association:** this sample opens a fresh SOCKS5 association per invocation. For a long-running client you can reuse the `Socks5UdpClient` + `Socks5UdpRelay` and make multiple requests through the same `HttpClient`.

## Security

This sample sets `RemoteCertificateValidationCallback => true`, which **disables TLS certificate validation**. It exists purely to keep the demo runnable against arbitrary endpoints — **do not copy this into production code**. For real use, replace the callback with one that validates the chain against a real trust store and pins/checks the SAN against `SslOptions.TargetHost`.
