using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace Socks5Server;

class Program
{
    static async Task Main(string[] args)
    {
        using var loggerFactory = LoggerFactory.Create(b =>
            b.AddSimpleConsole(o =>
            {
                o.TimestampFormat = "yyyy-MM-dd HH:mm:ss ";
                o.SingleLine = true;
            }).SetMinimumLevel(LogLevel.Debug));

        var logger = loggerFactory.CreateLogger<Program>();
        var server = new Socks5Listener(IPAddress.Any, 1080, loggerFactory);

        logger.LogInformation("SOCKS5 server starting on 0.0.0.0:1080 [CONNECT + UDP ASSOCIATE]");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        await server.RunAsync(cts.Token);
        logger.LogInformation("Shutting down.");
    }
}
