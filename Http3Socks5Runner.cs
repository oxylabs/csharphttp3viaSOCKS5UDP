using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;

namespace Http3Socks5Demo;

/// <summary>
/// Performs a single HTTP/3 GET through the loopback shim.
///
/// The shim's loopback endpoint is used as the URI authority so MsQuic dials
/// 127.0.0.1, while <c>SslOptions.TargetHost</c> + <c>Host</c> header keep
/// SNI and <c>:authority</c> pointing at the real origin.
/// </summary>
internal static class Http3Socks5Runner
{
    public static async Task<int> RunAsync(
        string targetHost,
        ushort targetPort,
        int loopbackPort,
        string body,
        CancellationToken cancellationToken)
    {
        var handler = new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = targetHost,
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
                EnabledSslProtocols = SslProtocols.Tls13,
                ApplicationProtocols =
                [
                    SslApplicationProtocol.Http3,
                ],
            },
            ConnectTimeout = TimeSpan.FromSeconds(40),
        };

        using var client = new HttpClient(handler)
        {
            DefaultRequestVersion = HttpVersion.Version30,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Timeout = TimeSpan.FromSeconds(60),
        };

        var uri = new Uri($"https://127.0.0.1:{loopbackPort}/");
        using var request = new HttpRequestMessage(HttpMethod.Get, uri)
        {
            Version = HttpVersion.Version30,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        if (!string.IsNullOrEmpty(body))
        {
            var content = new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes(body)));
            content.Headers.ContentLength = null;
            request.Content = content;
        }
        // :authority sent to the origin; without this, the upstream sees 127.0.0.1.
        request.Headers.Host = targetPort == 443 ? targetHost : $"{targetHost}:{targetPort}";

        using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken).ConfigureAwait(false);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        Console.WriteLine($"Status:   {(int)response.StatusCode} {response.StatusCode}");
        Console.WriteLine($"Protocol: HTTP/{response.Version}");
        Console.WriteLine("Response:");
        Console.Write(responseBody);
        if (!responseBody.EndsWith('\n'))
        {
            Console.WriteLine();
        }

        return (int)response.StatusCode;
    }
}
