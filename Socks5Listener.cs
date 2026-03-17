using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace Socks5Server;

/// <summary>
/// Accepts TCP connections and dispatches each to a <see cref="Socks5Session"/>.
/// </summary>
internal sealed class Socks5Listener
{
    private readonly IPAddress _host;
    private readonly int _port;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<Socks5Listener> _logger;

    public Socks5Listener(IPAddress host, int port, ILoggerFactory loggerFactory)
    {
        _host = host;
        _port = port;
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<Socks5Listener>();
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var listener = new TcpListener(_host, _port);
        listener.Start();
        _logger.LogInformation("Listening on {endpoint}", listener.LocalEndpoint);

        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                // Fire-and-forget: each session runs independently
                _ = Task.Run(() => HandleClientAsync(client, ct), ct);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            listener.Stop();
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        var remote = client.Client.RemoteEndPoint;
        _logger.LogInformation("Connection from {remote}", remote);
        try
        {
            using (client)
            {
                var session = new Socks5Session(
                    client,
                    _loggerFactory.CreateLogger<Socks5Session>());
                await session.RunAsync(ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning("Session {remote} ended: {msg}", remote, ex.Message);
        }
    }
}
