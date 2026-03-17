using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace Socks5Server;

/// <summary>
/// Bidirectional UDP relay for one SOCKS5 UDP ASSOCIATE session.
///
/// Client → relay:
///     Receives SOCKS5-framed datagrams, strips header, forwards raw
///     payload to the real destination.
///
/// Target → relay:
///     Receives raw reply, prepends SOCKS5 header, forwards to client.
///
/// The client's real address is unknown at ASSOCIATE time (tun2socks sends
/// 0.0.0.0:0 as the hint). It is learned from the first datagram received.
///
/// DNS resolution uses <see cref="Dns.GetHostAddressesAsync"/> — fully async,
/// no thread-pool workaround needed (.NET handles this natively).
/// </summary>
internal sealed class UdpRelay
{
    private readonly UdpClient _socket;
    private readonly ILogger _logger;
    private IPEndPoint? _clientEndPoint;   // learned from first datagram
    private CancellationTokenSource? _cts;

    public UdpRelay(IPAddress bindAddress, ILogger logger)
    {
        _logger = logger;
        // Bind on given address, port 0 → ephemeral
        _socket = new UdpClient(new IPEndPoint(bindAddress, 0));
    }

    public IPEndPoint LocalEndPoint =>
        (IPEndPoint)_socket.Client.LocalEndPoint!;

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _ = Task.Run(() => ReceiveLoopAsync(_cts.Token));
    }

    public void Stop()
    {
        _cts?.Cancel();
        try { _socket.Close(); } catch { }
        _logger.LogInformation("UDP relay stopped on {ep}", LocalEndPoint);
    }

    // -------------------------------------------------------------------------
    // Main receive loop
    // -------------------------------------------------------------------------

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        _logger.LogInformation("UDP relay receive loop started on {ep}", LocalEndPoint);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                UdpReceiveResult result;
                try
                {
                    result = await _socket.ReceiveAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (SocketException ex)
                {
                    _logger.LogWarning("UDP relay socket error: {msg}", ex.Message);
                    break;
                }

                // Learn client address from first packet
                if (_clientEndPoint is null)
                {
                    _clientEndPoint = result.RemoteEndPoint;
                    _logger.LogInformation("UDP relay: client addr learned as {ep}", _clientEndPoint);
                }

                if (result.RemoteEndPoint.Equals(_clientEndPoint))
                    _ = Task.Run(() => FromClientAsync(result.Buffer, ct), ct);
                else
                    FromTarget(result.Buffer, result.RemoteEndPoint);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug("UDP relay loop ended: {msg}", ex.Message);
        }
    }

    // -------------------------------------------------------------------------
    // Client → target
    // -------------------------------------------------------------------------

    private async Task FromClientAsync(byte[] data, CancellationToken ct)
    {
        var parsed = ParseUdpHeader(data);
        if (parsed is null)
        {
            _logger.LogWarning("UDP relay: malformed header from client, dropping");
            return;
        }

        var (frag, dstHost, dstPort, payload) = parsed.Value;

        if (frag != 0)
        {
            // Fragmentation not supported — drop silently
            _logger.LogDebug("UDP relay: dropping fragmented datagram (frag={frag})", frag);
            return;
        }

        try
        {
            // Fully async DNS — no blocking, no executor needed
            var addresses = await Dns.GetHostAddressesAsync(dstHost, ct);
            if (addresses.Length == 0) return;

            var dstEp = new IPEndPoint(addresses[0], dstPort);
            await _socket.SendAsync(payload, payload.Length, dstEp);
            _logger.LogDebug("UDP → {host}:{port}  {len}B", dstHost, dstPort, payload.Length);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.LogWarning("UDP relay: send to {host}:{port} failed: {msg}",
                dstHost, dstPort, ex.Message);
        }
    }

    // -------------------------------------------------------------------------
    // Target → client
    // -------------------------------------------------------------------------

    private void FromTarget(byte[] data, IPEndPoint srcEp)
    {
        if (_clientEndPoint is null) return;

        var wrapped = BuildUdpHeader(srcEp.Address, srcEp.Port, data);
        try
        {
            _socket.Send(wrapped, wrapped.Length, _clientEndPoint);
            _logger.LogDebug("UDP ← {ep}  {len}B", srcEp, data.Length);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("UDP relay: reply to client failed: {msg}", ex.Message);
        }
    }

    // -------------------------------------------------------------------------
    // SOCKS5 UDP framing  (RFC 1928 §7)
    //
    //  +-----+------+------+----------+----------+----------+
    //  | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    //  +-----+------+------+----------+----------+----------+
    //  |  2  |  1   |  1   | variable |    2     | variable |
    //  +-----+------+------+----------+----------+----------+
    // -------------------------------------------------------------------------

    private static (byte frag, string host, int port, byte[] payload)?
        ParseUdpHeader(byte[] data)
    {
        if (data.Length < 4) return null;

        byte frag = data[2];
        byte atyp = data[3];
        int offset = 4;
        string host;

        switch (atyp)
        {
            case Socks5.AtypIPv4:
                if (data.Length < offset + 6) return null;
                host = new IPAddress(data[offset..(offset + 4)]).ToString();
                offset += 4;
                break;
            case Socks5.AtypIPv6:
                if (data.Length < offset + 18) return null;
                host = new IPAddress(data[offset..(offset + 16)]).ToString();
                offset += 16;
                break;
            case Socks5.AtypDomain:
                if (data.Length < offset + 1) return null;
                int dlen = data[offset++];
                if (data.Length < offset + dlen + 2) return null;
                host = System.Text.Encoding.ASCII.GetString(data, offset, dlen);
                offset += dlen;
                break;
            default:
                return null;
        }

        if (data.Length < offset + 2) return null;
        int port = (data[offset] << 8) | data[offset + 1];
        offset += 2;

        return (frag, host, port, data[offset..]);
    }

    private static byte[] BuildUdpHeader(IPAddress srcAddr, int srcPort, byte[] payload)
    {
        byte[] addrBytes;
        byte atyp;

        if (srcAddr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            atyp = Socks5.AtypIPv6;
            addrBytes = srcAddr.GetAddressBytes();
        }
        else
        {
            atyp = Socks5.AtypIPv4;
            addrBytes = srcAddr.MapToIPv4().GetAddressBytes();
        }

        // RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT(2) + DATA
        var header = new byte[4 + addrBytes.Length + 2];
        header[0] = 0x00; // RSV
        header[1] = 0x00; // RSV
        header[2] = 0x00; // FRAG
        header[3] = atyp;
        addrBytes.CopyTo(header, 4);
        header[4 + addrBytes.Length]     = (byte)(srcPort >> 8);
        header[4 + addrBytes.Length + 1] = (byte)(srcPort & 0xFF);

        var result = new byte[header.Length + payload.Length];
        header.CopyTo(result, 0);
        payload.CopyTo(result, header.Length);
        return result;
    }
}
