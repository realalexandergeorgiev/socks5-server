using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace Socks5Server;

/// <summary>
/// Handles one SOCKS5 TCP control connection.
/// Implements CONNECT (RFC 1928 §6) and UDP ASSOCIATE (RFC 1928 §7).
/// </summary>
internal sealed class Socks5Session
{
    private readonly TcpClient _client;
    private readonly ILogger<Socks5Session> _logger;
    private NetworkStream _stream = null!;

    public Socks5Session(TcpClient client, ILogger<Socks5Session> logger)
    {
        _client = client;
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        _stream = _client.GetStream();
        await NegotiateAuthAsync(ct);
        await HandleRequestAsync(ct);
    }

    // -------------------------------------------------------------------------
    // Auth negotiation — no-auth only
    // -------------------------------------------------------------------------

    private async Task NegotiateAuthAsync(CancellationToken ct)
    {
        // VER + NMETHODS
        var header = await ReadExactAsync(2, ct);
        if (header[0] != Socks5.Ver)
            throw new ProtocolException($"Not SOCKS5 (ver={header[0]:X2})");

        var methods = await ReadExactAsync(header[1], ct);
        if (!methods.Contains(Socks5.AuthNone))
        {
            await _stream.WriteAsync(new byte[] { Socks5.Ver, Socks5.AuthNoMatch }, ct);
            throw new ProtocolException("No acceptable auth method");
        }

        await _stream.WriteAsync(new byte[] { Socks5.Ver, Socks5.AuthNone }, ct);
    }

    // -------------------------------------------------------------------------
    // Request dispatcher
    // -------------------------------------------------------------------------

    private async Task HandleRequestAsync(CancellationToken ct)
    {
        var header = await ReadExactAsync(4, ct);
        if (header[0] != Socks5.Ver)
            throw new ProtocolException($"Bad request ver={header[0]:X2}");

        byte cmd  = header[1];
        byte atyp = header[3];

        (string dstHost, int dstPort) = await ReadAddressAsync(atyp, ct);

        switch (cmd)
        {
            case Socks5.CmdConnect:
                await HandleConnectAsync(dstHost, dstPort, ct);
                break;
            case Socks5.CmdUdpAssoc:
                await HandleUdpAssociateAsync(dstHost, dstPort, ct);
                break;
            default:
                await SendReplyAsync(Socks5.RepCmdUnsup, ct: ct);
                throw new ProtocolException($"Unsupported CMD {cmd:X2}");
        }
    }

    // -------------------------------------------------------------------------
    // Address parsing
    // -------------------------------------------------------------------------

    private async Task<(string host, int port)> ReadAddressAsync(byte atyp, CancellationToken ct)
    {
        string host;
        switch (atyp)
        {
            case Socks5.AtypIPv4:
            {
                var raw = await ReadExactAsync(4, ct);
                host = new IPAddress(raw).ToString();
                break;
            }
            case Socks5.AtypIPv6:
            {
                var raw = await ReadExactAsync(16, ct);
                host = new IPAddress(raw).ToString();
                break;
            }
            case Socks5.AtypDomain:
            {
                var lenBuf = await ReadExactAsync(1, ct);
                var raw = await ReadExactAsync(lenBuf[0], ct);
                host = System.Text.Encoding.ASCII.GetString(raw);
                break;
            }
            default:
                await SendReplyAsync(Socks5.RepAtypUnsup, ct: ct);
                throw new ProtocolException($"Unsupported ATYP {atyp:X2}");
        }

        var portBuf = await ReadExactAsync(2, ct);
        int port = (portBuf[0] << 8) | portBuf[1];
        return (host, port);
    }

    // -------------------------------------------------------------------------
    // CONNECT
    // -------------------------------------------------------------------------

    private async Task HandleConnectAsync(string dstHost, int dstPort, CancellationToken ct)
    {
        _logger.LogInformation("CONNECT → {host}:{port}", dstHost, dstPort);

        var target = new TcpClient();
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));
            await target.ConnectAsync(dstHost, dstPort, timeoutCts.Token);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
        {
            target.Dispose();
            await SendReplyAsync(Socks5.RepRefused, ct: ct);
            throw;
        }
        catch
        {
            target.Dispose();
            await SendReplyAsync(Socks5.RepFailure, ct: ct);
            throw;
        }

        using (target)
        {
            var bindEp = (IPEndPoint)target.Client.LocalEndPoint!;
            await SendReplyAsync(Socks5.RepSuccess, bindEp.Address, bindEp.Port, ct);
            _logger.LogInformation("TCP tunnel up → {host}:{port}", dstHost, dstPort);

            var targetStream = target.GetStream();
            await Task.WhenAll(
                _stream.CopyToAsync(targetStream, ct),
                targetStream.CopyToAsync(_stream, ct)
            );
        }
        _logger.LogInformation("TCP tunnel down ← {host}:{port}", dstHost, dstPort);
    }

    // -------------------------------------------------------------------------
    // UDP ASSOCIATE
    // -------------------------------------------------------------------------

    private async Task HandleUdpAssociateAsync(string hintHost, int hintPort, CancellationToken ct)
    {
        _logger.LogInformation("UDP ASSOCIATE (hint {host}:{port})", hintHost, hintPort);

        // Bind UDP relay socket on same IP as the TCP server accepted on,
        // port 0 → OS picks an ephemeral port.
        var serverIp = ((IPEndPoint)_client.Client.LocalEndPoint!).Address;
        var relay = new UdpRelay(serverIp, _logger);

        try
        {
            relay.Start();
            var bindEp = relay.LocalEndPoint;
            _logger.LogInformation("UDP relay bound on {ep}", bindEp);

            await SendReplyAsync(Socks5.RepSuccess, bindEp.Address, bindEp.Port, ct);

            // RFC 1928: UDP relay MUST be torn down when TCP control connection closes.
            await DrainUntilClosedAsync(ct);
        }
        finally
        {
            relay.Stop();
            _logger.LogInformation("UDP ASSOCIATE ended");
        }
    }

    /// <summary>
    /// Reads (and discards) bytes from the TCP control connection until
    /// EOF, cancellation, or error — whichever comes first.
    /// </summary>
    private async Task DrainUntilClosedAsync(CancellationToken ct)
    {
        var buf = new byte[256];
        try
        {
            while (true)
            {
                int n = await _stream.ReadAsync(buf, ct);
                if (n == 0) break; // clean EOF
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException)
        {
            // Connection reset or cancelled — normal teardown
        }
    }

    // -------------------------------------------------------------------------
    // Reply builder
    // -------------------------------------------------------------------------

    private async Task SendReplyAsync(
        byte rep,
        IPAddress? bindAddr = null,
        int bindPort = 0,
        CancellationToken ct = default)
    {
        bindAddr ??= IPAddress.Any;

        byte atyp;
        byte[] addrBytes;

        if (bindAddr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            atyp = Socks5.AtypIPv6;
            addrBytes = bindAddr.GetAddressBytes(); // 16 bytes
        }
        else
        {
            atyp = Socks5.AtypIPv4;
            addrBytes = bindAddr.MapToIPv4().GetAddressBytes(); // 4 bytes
        }

        // VER REP RSV ATYP ADDR PORT
        var reply = new byte[4 + addrBytes.Length + 2];
        reply[0] = Socks5.Ver;
        reply[1] = rep;
        reply[2] = 0x00;
        reply[3] = atyp;
        addrBytes.CopyTo(reply, 4);
        reply[4 + addrBytes.Length]     = (byte)(bindPort >> 8);
        reply[4 + addrBytes.Length + 1] = (byte)(bindPort & 0xFF);

        await _stream.WriteAsync(reply, ct);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private async Task<byte[]> ReadExactAsync(int count, CancellationToken ct)
    {
        var buf = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            int n = await _stream.ReadAsync(buf.AsMemory(offset, count - offset), ct);
            if (n == 0)
                throw new EndOfStreamException("Connection closed mid-read");
            offset += n;
        }
        return buf;
    }
}

internal sealed class ProtocolException : Exception
{
    public ProtocolException(string msg) : base(msg) { }
}
