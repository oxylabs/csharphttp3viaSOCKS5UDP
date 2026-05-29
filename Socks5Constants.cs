namespace Http3Socks5Demo;

/// <summary>
/// SOCKS5 (RFC 1928) and user/password sub-negotiation (RFC 1929) byte
/// constants shared by the control-plane client and the UDP relay shim.
/// </summary>
internal static class Socks5Constants
{
    public const byte SocksVersion = 0x05;

    /// <summary>RFC 1929 user/password sub-negotiation version.</summary>
    public const byte AuthSubVersion = 0x01;

    public const byte AuthNone = 0x00;
    public const byte AuthUserPass = 0x02;
    public const byte AuthNoneAcceptable = 0xFF;

    public const byte CommandUdpAssociate = 0x03;

    public const byte AddressTypeIPv4 = 0x01;
    public const byte AddressTypeDomain = 0x03;
    public const byte AddressTypeIPv6 = 0x04;

    public const byte ReplySucceeded = 0x00;
}
