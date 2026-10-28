# Star Wars Battlefront II (2005) 1.1 – LAN play over Tailscale

This lets you play the 2005 Star Wars Battlefront II's **LAN multiplayer** with friends over the internet, using [Tailscale](https://tailscale.com). It uses a drop-in `dinput8.dll` and changes no game files.

On a real LAN, the game finds servers by broadcasting, and broadcasts don't cross Tailscale. The proxy turns server discovery into direct, point-to-point packets. It also works around problems in the game itself:
- The game refuses Tailscale's `100.x` addresses.
- `/norender` crashes the dedicated server at start-up. With the proxy, a server can run without 3D rendering.
- The join code has a socket bug, inherited from Battlefront (2004).

It is the Battlefront II port of [Battlefront (2004) 1.3.7 – LAN play over Tailscale](https://github.com/afrowebster/Battlefront-2004-1.3.7-GoG-Steam-version-Tailscale-LAN).

**For:** the **GOG version 1.1** of Battlefront II. Tested with a dedicated server in a Windows 10 VM and a remote Windows 11 client. The exact exe it was tested on is identified by SHA-256 in [FINDINGS.md](FINDINGS.md).

**Steam:** untested. The address alias, the discovery redirect and the `/norender` fix don't depend on the exact build. The join-bug workaround checks the code bytes of the exe and switches itself off on any build it doesn't recognise. The log tells you which case applies.

## Quick start

1. Install Tailscale on the **server machine** and on every **client**, all on the same tailnet. If the server runs in a VM, install Tailscale inside the VM.
2. Get `dinput8.dll` from the [Releases](../../releases) page, or build it yourself (see below). Copy it into `GameData\` on every machine.
3. **Server:**
   - Copy `examples/server/BattlefrontIIDirectIp.ini` into `GameData\`.
   - Edit the variables at the top of `examples/server/BF2 dedicated.bat`, at least `GAMEDIR`, and run it.
4. **Each client:**
   - Copy `examples/client/BattlefrontIIDirectIp.ini` into `GameData\`.
   - Set `Server=` to the server's Tailscale IPv4 address (run `tailscale ip -4` on the server).
5. Start the game on the client and open the LAN server browser. A server at `100.A.B.C` is listed as `10.A.B.C`. This is expected; the proxy translates between the two.

Allow the game's UDP ports on the **server and every client**. Windows often treats the Tailscale adapter as a Public network. In an admin PowerShell:

```powershell
New-NetFirewallRule -DisplayName "Battlefront II UDP (Tailscale)" -Direction Inbound -Protocol UDP -LocalPort 3656,3658,3659 -Action Allow -Profile Any
```

## Dedicated-server options

`examples/server/BF2 dedicated.bat` builds the command line from the variables at its top. It prints the command before starting the game.

| Variable | Default | Effect |
|---|---|---|
| `MAPS` | `tat2g_con` | Map rotation, as mission names. Each can be followed by two reinforcement counts. |
| `MINPLAYERS` | 1 | `/playercount`: the number of players before the match starts. The game's default is 2. |
| `MAXPLAYERS` | 64 | `/playerlimit` |
| `BOTS` | -1 | `/bots`: AI count. -1 keeps each mission's default. |
| `SKILL` | 2 | `/skill`: AI difficulty, 1–3 |
| `TPS` | 60 | `/tps`: network tick rate. The game's default of 20 adds about 50 ms to the in-game ping. **Never use 0**: the game deliberately crashes on it. |
| `NORENDER` | 1 | `/norender`: a text-only server window that saves CPU and GPU. It **needs the proxy DLL**; without it, the game exits at once. |
| `HEROES`, `TEAMDAMAGE`, `SHOWNAMES` | 1 | 0 turns them off: `/heroes 0`, `/noteamdamage`, `/nonames` |
| `AUTOASSIGN` | 0 | 0 adds `/sideselect`, so players choose and switch sides |
| `PASSWORD`, `ADMINPW` | empty | `/password` (untested) and `/adminpw` |
| `EXTRA` | empty | Extra switches, passed through as typed, e.g. the hero tuning switches |

`/lan` is always set and is required. Without it, the server uses GOG Galaxy and is invisible to LAN clients. [FINDINGS.md](FINDINGS.md) lists every known switch, its default and the reasoning.

## Troubleshooting

Each launch writes `GameData\BattlefrontIIDirectIp.log`. A healthy client log contains:

```
mode=client server=100.x.y.z
hooks: bind=1 closesocket=1 connect=1 recvfrom=1 send=1 sendto=1
proxy active
connect socket=... broadcast:3656 redirected to 100.x.y.z:3656
recvfrom discovery socket=... (41 bytes) 100.x.y.z:...
game socket fix available: ...
sendto socket=... (69 bytes) to 100.x.y.z:3658 (unmapped from 10.x) ...: 04 ff ff ...
```

A healthy server log shows `recvfrom discovery ... (13 bytes) 100.x...` followed by `discovery reply ... unicast to ...`. With `/norender` it also shows `norender fix: D3DXCheckTextureRequirements hook=1`.

| Symptom | Likely cause |
|---|---|
| No probes in the server log | Firewall on the server, or a wrong `Server=` on the client |
| Probes and replies in the server log, but no replies in the client log | Firewall on the client (inbound UDP 3656) |
| Server opens no ports | `/lan` missing |
| `/norender` server closes at once with exit code 0 | The proxy DLL is missing or not in `GameData\` |
| The game closes silently | Look for `first-chance exception` and `process exiting` in the log; they show where it crashed |
| Client crashes when the server appears (`0x80000003`) | The proxy is missing or inactive on the client |
| Join times out with `sendto socket=0 ... error=10038` | The game-socket workaround is unavailable for this exe build (see the `game socket fix` log line) |
| High in-game ping | Raise `TPS` (`/tps`) on the server |
| `/autonet client` shows only a black screen with **Back** | It joins only a server whose name matches its `/gamename`. Use the LAN browser instead. |

To test a server and a client on **one** machine, add `TestDiscoveryReplyPort=3657` to both ini files, and point the client at the machine's own Tailscale IP. Without it, both instances share UDP 3656 and the discovery reply can go to the wrong one.

## Build

This needs Visual Studio 2022 Build Tools with the C++ workload. Run `build.bat`; the output is `src\dinput8.dll` (32-bit).

## How it works

[FINDINGS.md](FINDINGS.md) has the full reverse-engineering notes:
- the game's sockets, ports and discovery protocol, compared with Battlefront (2004)
- the hashed command-line switches and their defaults
- the RFC 1918 assertion and the address alias
- why `/norender` crashed, and how the crash was hidden
- the join socket race

`ghidra_scripts/` contains the headless Ghidra helpers used for the analysis.

## License

Copyright (C) 2026 afrowebster

Licensed under the [GNU General Public License v3.0](LICENSE). You may use, change and share this project, but if you distribute it, or a modified version, you must do so under the same licence and make the source code available. This covers the code and documentation in this repository only. Star Wars Battlefront II and its files remain the property of their respective owners, and none of them are included here.

## Disclaimer

This is an unofficial fan project, not affiliated with Lucasfilm, Disney, Pandemic, Aspyr, GOG or Valve. It modifies the running game process in memory to change its networking behaviour. Use it at your own risk, and only with games you own.
