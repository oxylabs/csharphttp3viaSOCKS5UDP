using System.Diagnostics;

namespace Http3Socks5Demo;

internal static class Program
{
    private const string DefaultProxyHost = "socks.pr.oxylabs.io:7777";
    private const string DefaultTargetHost = "echo-udp.oxylabs.io";
    private const int DefaultProxyPort = 1080;
    private const ushort DefaultTargetPort = 443;

    public static async Task<int> Main(string[] args)
    {
        ParseResult parseResult = TryParseArgs(args, out Options? opts, out var error);
        switch (parseResult)
        {
            case ParseResult.HelpRequested:
                PrintUsage(Console.Out);
                return 0;
            case ParseResult.Error:
                await Console.Error.WriteLineAsync(error).ConfigureAwait(false);
                PrintUsage(Console.Error);
                return 2;
        }

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        var sw = Stopwatch.StartNew();
        int exitCode;
        try
        {
            exitCode = await RunAsync(opts, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"failed to perform HTTP3 request via proxy: {ex}").ConfigureAwait(false);
            exitCode = 1;
        }
        sw.Stop();

        Console.WriteLine($"Request took: {sw.ElapsedMilliseconds} ms");
        return exitCode;
    }

    private static async Task<int> RunAsync(Options opts, CancellationToken ct)
    {
        await using Socks5UdpClient udpClient = await Socks5UdpClient.ConnectAsync(
            opts.ProxyHost,
            opts.ProxyPort,
            opts.Username,
            opts.Password,
            ct).ConfigureAwait(false);

        await using var relay = Socks5UdpRelay.Start(
            udpClient.RelayEndPoint,
            opts.TargetHost,
            opts.TargetPort);

        int statusCode = await Http3Socks5Runner.RunAsync(
            opts.TargetHost,
            opts.TargetPort,
            relay.LocalPort,
            opts.Body,
            ct).ConfigureAwait(false);

        return IsSuccessStatus(statusCode) ? 0 : 1;
    }

    private static bool IsSuccessStatus(int statusCode) => statusCode is >= 200 and < 400;

    private static ParseResult TryParseArgs(string[] args, out Options options, out string error)
    {
        string username = string.Empty;
        string password = string.Empty;
        string proxySpec = DefaultProxyHost;
        string targetSpec = DefaultTargetHost;
        string body = string.Empty;

        options = null!;
        error = string.Empty;
        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg is "--help" or "-help" or "/?")
            {
                return ParseResult.HelpRequested;
            }

            if (i + 1 >= args.Length)
            {
                error = $"flag '{arg}' requires a value";
                return ParseResult.Error;
            }
            var value = args[++i];

            switch (arg)
            {
                case "-u":
                    username = value;
                    break;
                case "-p":
                    password = value;
                    break;
                case "-h":
                    proxySpec = value;
                    break;
                case "-t":
                    targetSpec = value;
                    break;
                case "-body":
                    body = value;
                    break;
                default:
                    error = $"unknown flag '{arg}'";
                    return ParseResult.Error;
            }
        }

        if (!TryParseHostPort(proxySpec, DefaultProxyPort, out var proxyHost, out var proxyPort, out error))
        {
            error = $"-h {error}";
            return ParseResult.Error;
        }
        if (!TryParseHostPort(targetSpec, DefaultTargetPort, out var targetHost, out var targetPortInt, out error))
        {
            error = $"-t {error}";
            return ParseResult.Error;
        }

        options = new Options(
            Username: username,
            Password: password,
            ProxyHost: proxyHost,
            ProxyPort: proxyPort,
            TargetHost: targetHost,
            TargetPort: (ushort)targetPortInt,
            Body: body);
        return ParseResult.Ok;
    }

    /// <summary>
    /// Parses <c>host</c> or <c>host:port</c>. When the port is omitted, falls back
    /// to <paramref name="defaultPort"/>.
    /// </summary>
    private static bool TryParseHostPort(string spec, int defaultPort, out string host, out int port, out string error)
    {
        host = string.Empty;
        port = defaultPort;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(spec))
        {
            error = "host must not be empty";
            return false;
        }

        int idx = spec.LastIndexOf(':');
        if (idx < 0)
        {
            host = spec;
            return true;
        }

        if (idx == 0 || idx == spec.Length - 1)
        {
            error = $"'{spec}' is not a valid host[:port]";
            return false;
        }

        host = spec[..idx];
        var portStr = spec[(idx + 1)..];
        if (!int.TryParse(portStr, out port) || port is <= 0 or > 65535)
        {
            error = $"'{spec}' has invalid port '{portStr}'";
            return false;
        }
        return true;
    }

    private static void PrintUsage(TextWriter writer)
    {
        writer.WriteLine();
        writer.WriteLine("Usage: http3viasocks5udp [flags]");
        writer.WriteLine();
        writer.WriteLine("  -body string");
        writer.WriteLine("        optional request body");
        writer.WriteLine("  -h host[:port]");
        writer.WriteLine($"        proxy host, default port {DefaultProxyPort} (default \"{DefaultProxyHost}\")");
        writer.WriteLine("  -p string");
        writer.WriteLine("        proxy password");
        writer.WriteLine("  -t host[:port]");
        writer.WriteLine($"        target host, default port {DefaultTargetPort} (default \"{DefaultTargetHost}\")");
        writer.WriteLine("  -u string");
        writer.WriteLine("        proxy username");
    }

    private enum ParseResult
    {
        Ok,
        HelpRequested,
        Error,
    }

    private sealed record Options(
        string Username,
        string Password,
        string ProxyHost,
        int ProxyPort,
        string TargetHost,
        ushort TargetPort,
        string Body);
}
