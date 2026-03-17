namespace Socks5Server;

internal static class Socks5
{
    // Version
    public const byte Ver         = 0x05;

    // Auth methods
    public const byte AuthNone    = 0x00;
    public const byte AuthNoMatch = 0xFF;

    // Commands
    public const byte CmdConnect  = 0x01;
    public const byte CmdUdpAssoc = 0x03;

    // Address types
    public const byte AtypIPv4    = 0x01;
    public const byte AtypDomain  = 0x03;
    public const byte AtypIPv6    = 0x04;

    // Reply codes
    public const byte RepSuccess    = 0x00;
    public const byte RepFailure    = 0x01;
    public const byte RepRefused    = 0x05;
    public const byte RepCmdUnsup   = 0x07;
    public const byte RepAtypUnsup  = 0x08;
}
