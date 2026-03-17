# socks5-server-cs

A minimal, async SOCKS5 proxy server written in C# / .NET 8 — no NuGet dependencies, single self-contained executable.

Feature-equivalent to [pysocks](https://github.com/realalexandergeorgiev/pysocks) (Python) with additional TLS and username/password authentication support.

## Features

- **CONNECT** — full TCP proxy with bidirectional async relay
- **UDP ASSOCIATE** — RFC 1928 §7 compliant, designed for tun2socks
- **TLS** — encrypted transport for the SOCKS5 control channel
- **Username/password auth** — RFC 1929 sub-negotiation
- IPv4, IPv6, and domain name targets
- Fully async (`Task`, `async/await`, no blocking calls)
- No NuGet dependencies — stdlib only (`System.Net`, `System.Net.Security`)
- Publishes as a single self-contained executable

## Requirements

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (build only — runtime is bundled in the exe)

## Build

```bash
# Linux / macOS
dotnet publish -c Release -r linux-x64
# or size optimized Windows x64
dotnet publish -r win-x64 -c Release -p:PublishSingleFile=true -p:PublishTrimmed=true --self-contained true

# Windows
dotnet publish -c Release -r win-x64

# Output lands in:
# bin/Release/net8.0/<rid>/publish/socks5-server
```

Cross-compilation works — build a Windows exe from Linux and vice versa by changing the `-r` RID.

### Supported RIDs

| Target | RID |
|---|---|
| Linux x64 | `linux-x64` |
| Linux ARM64 | `linux-arm64` |
| Windows x64 | `win-x64` |
| macOS x64 | `osx-x64` |
| macOS ARM64 | `osx-arm64` |

## Configuration

> **TODO:** document cert source (pfx / self-signed / both) and credential location (constants / appsettings.json / CLI) once confirmed.

Placeholder — the following options will be available:

| Option | Description | Default |
|---|---|---|
| `--host` | Listening interface | `0.0.0.0` |
| `--port` | Listening port | `1080` |
| `--cert` | Path to `.pfx` certificate | *(TBD)* |
| `--cert-pass` | Certificate password | *(TBD)* |
| `--user` | SOCKS5 username | *(TBD)* |
| `--pass` | SOCKS5 password | *(TBD)* |

## Usage

```bash
# TBD — depends on confirmed config approach
./socks5-server --port 1080
```

## tun2socks integration

Same as the Python version — tun2socks is the SOCKS5 client, this server is the backend.

> **Note:** tun2socks itself does not support TLS on the SOCKS5 connection. If you enable TLS here, you need a TLS terminator between tun2socks and this server (e.g. `stunnel`, `socat`, or an SSH tunnel). Alternatively, disable TLS for local/lab use.

### xjasonlyu/tun2socks

```bash
sudo ip tuntap add name tun0 mode tun
sudo ip link set tun0 up
tun2socks -device tun0 -proxy socks5://127.0.0.1:1080
sudo ip route add default dev tun0 metric 1
```

### hev-socks5-tunnel

```yaml
tunnel:
  name: tun0
  mtu: 8500
  ipv4: 198.18.0.1
socks5:
  address: 127.0.0.1
  port: 1080
  udp: udp
  username: youruser
  password: yourpass
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        tun2socks                        │
│         (TUN interface → SOCKS5 client)                 │
└────────────────────┬────────────────────────────────────┘
                     │ TCP (optionally TLS)
                     ▼
┌─────────────────────────────────────────────────────────┐
│                   socks5-server (C#)                    │
│                                                         │
│  TcpListener :1080                                      │
│  └── SslStream (optional TLS)                           │
│       ├── Auth negotiation  (RFC 1929)                  │
│       ├── CONNECT  → Task-based bidirectional relay     │
│       └── UDP ASSOCIATE → UdpClient relay task          │
│            ├── client → strip header → target           │
│            └── target → prepend header → client         │
└────────────────────┬────────────────────────────────────┘
                     │ raw TCP / raw UDP
                     ▼
              real network targets
```

## Protocol support

| Command | Status |
|---|---|
| CONNECT | ✅ |
| UDP ASSOCIATE | ✅ |
| BIND | ❌ not implemented |

| Auth method | Status |
|---|---|
| No auth (0x00) | ✅ |
| Username/password (0x02, RFC 1929) | ✅ |

| Address type | Status |
|---|---|
| IPv4 | ✅ |
| IPv6 | ✅ |
| Domain name | ✅ (via `Dns.GetHostAddressesAsync`) |

## Differences from the Python version

| | Python | C# |
|---|---|---|
| TLS | ❌ | ✅ `SslStream` |
| Auth | ❌ no-auth only | ✅ RFC 1929 |
| Async DNS | `run_in_executor` workaround | Native `Dns.GetHostAddressesAsync` |
| Deployment | Requires Python 3.8+ | Single self-contained exe, no runtime needed |
| UDP relay concurrency | `asyncio.ensure_future` per datagram | `Task.Run` per datagram |

## Limitations

- **TLS on SOCKS5 is non-standard** — most SOCKS5 clients do not support it natively. Pair with stunnel or use without TLS for standard client compatibility.
- **No BIND command** — not implemented.
- **UDP relay is IPv4-only** on the relay socket itself; IPv6 targets are reachable via DNS resolution.
- **Single user** — RFC 1929 auth supports one username/password pair.

## License

MIT
