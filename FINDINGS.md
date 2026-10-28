# Battlefront II (2005) LAN over Tailscale: findings

This is the reverse-engineering record behind the proxy. It ports the [Battlefront (2004) proxy](https://github.com/afrowebster/Battlefront-2004-1.3.7-GoG-Steam-version-Tailscale-LAN) to **Star Wars Battlefront II, GOG build**.

Everything below was verified in October 2026 on `BattlefrontII.exe` with SHA-256 `9737C82A16369918A67EC33F5E07205E7FF89FD05F556CC79CC11027416E5541` (GOG buildId 50834614945396236; the exe has no version resource), unless it is marked *unverified*. All addresses are Ghidra virtual addresses with image base 0x400000.

## Goal and result

The goal is BF2's LAN multiplayer between machines that share no broadcast domain and are connected only by Tailscale. The server is a dedicated server in a Windows 10 VM, and the client is a remote Windows 11 PC. There is no GOG Galaxy or GameSpy involvement, and no game file is changed.

**Result: working.** Discovery, join and play worked across the two machines, with no socket errors or timeouts. Tailscale had a direct (non-relayed) path with a 16–20 ms round trip. A `/norender` dedicated server also works, but only with the proxy (problem 2).

The solution has the same shape as BF1. A `dinput8.dll` proxy in `GameData\` hooks Winsock through the exe's import address table at runtime. The same DLL runs on both sides and reads its mode from an ini.

## Repository layout

| Path | What |
|---|---|
| `src/dinput8_proxy.cpp` | Proxy source, the complete implementation |
| `src/dinput8_proxy.def` | Exports `DirectInput8Create` only |
| `build.bat` | MSVC x86 build |
| `examples/` | Server and client ini files, and the dedicated-server batch file |
| `ghidra_scripts/` | Headless Ghidra helpers: `DecompileAt`, `RefsTo`, `ImportCallers` (every call site of a DLL's imports, works with ordinal imports), and `Disasm` (disassembles where Ghidra has no function) |

## Static facts

- The exe is PE x86 with image base 0x400000 and **ASLR on**. Compute every runtime address as `GetModuleHandle(NULL) + (VA - 0x400000)`.
  - `.text`: file offset 0x400 → VA 0x401000
  - `.rdata`: file 0x36AC00 → VA 0x76C000
  - `.data`: file 0x3DDC00 → VA 0x7DF000. Its raw size is 0x17600, so most of `.data` is BSS.
- The exe imports only `DINPUT8.dll!DirectInput8Create` from DirectInput, so the proxy uses the same host DLL as BF1. `ws2_32.dll` is a KnownDLL and can't be proxied.
- **WS2_32 is imported by ordinal**, as in BF1. The hooks match IAT slots by resolved address, not by name.
- **Command-line switches are matched by FNV-1a hash** of the lowercased name (offset 2166136261, prime 16777619), not by string. The parser is `FUN_00479740`, called from `FUN_004795a0`. Searching the exe for `"norender"` therefore finds nothing; search for its hash `0x75E8450E` instead.

## Networking architecture

| | BF1 | BF2 |
|---|---|---|
| Discovery port | 3657 | **3656** |
| Session port | 3658 | **3658 host, 3659 client**. `FUN_00618db0(char host)` uses base `DAT_007e9ef4`=3658, +1 when not host, and keeps incrementing on bind failure. |
| Broadcast send socket | `DAT_00940688` | `DAT_01faa710`, `connect()`ed to 255.255.255.255:3656 with `SO_BROADCAST` |
| Discovery receive socket | `DAT_0094068c` | `DAT_01faa714`, bound to 0.0.0.0:3656 with `SO_REUSEADDR` |
| Session socket | `DAT_00940690` | `DAT_01faa10c` |
| Create discovery / session | `FUN_005E8420` / `FUN_005E85E0` | `FUN_00618c80` / `FUN_00618db0` (**`__fastcall`, argument in CL**) |
| Close discovery / session | – / `FUN_005E8320` | `FUN_00618d80` / `FUN_00618ea0` |
| Send dispatcher / receive pump | `FUN_005E8F00` / `FUN_005E8AA0` | `FUN_00618ec0` / `FUN_00618fc0`. The dispatcher sends message type 0x44 with `send` on the broadcast socket, and everything else with `sendto` on the session socket. |
| RFC 1918 filter | `FUN_005B0F00` | `FUN_005d5a80` |
| `int3` on a non-RFC 1918 peer | `FUN_005AEAF0` | `FUN_005d77f0` (the net-address constructor) and `FUN_005d8820` |
| LAN vs Galaxy mode | `/lan` flag | `DAT_01fa39c5`, returned by `FUN_005b3670` and set by `FUN_005b3610` from Lua `ScriptCB_SetConnectType("LAN")`. When it is 0, all traffic goes through Galaxy (`gf::`). |

- **Discovery protocol:**
  - Probe, 13 bytes: `00 ff ff 00 00 | 4-byte nonce | 01 10 00 00`. The nonce is generated per search in `FUN_005d78d0`. BF1's tail was `04 10 00 00`.
  - Reply: `01 ff ff 00 00 | echoed nonce | …`. Its length depends on the server; 41 and 45 bytes were both observed.
  - The proxy identifies discovery traffic **by socket**, i.e. a bind to :3656 and a connect to broadcast:3656, not by byte pattern. It therefore doesn't depend on the packet layout.
- **Browser info query** on the session port: client `02 ff ff …` (13 bytes) → server `03 ff ff …` (53 bytes, bit-packed). Decoded at bit offset 4, it holds the server name, the game mode and the mission name. It carries **no IP addresses**.
- **Join:** client `04 ff ff …` (69 bytes) → server `06 …` (117–121 bytes). Then come `08`, `09`, `0a`, `0b`, `0c` and `10`–`14`, the load and sync traffic.
- **Advertised local address:** `FUN_005d87b0` takes the first RFC 1918 address from `gethostname`/`gethostbyname`. As in BF1, a host without one does not start hosting.
- **Socket-teardown race** (the same as BF1, but *not observed* in testing):
  - The browser stop paths `FUN_005d6ef0` and `FUN_005d7020` close the session socket unless `DAT_01e664e8 == 2`. But `DAT_01e664e8` is only ever written 0 or 1, so the guard never stops the close.
  - The proxy keeps the BF1 fix. A client `sendto(socket=0)` calls the game's `FUN_00618db0(0)`, writes the returned port to `DAT_01e64328`, and retries on the new socket.
  - The fix is guarded by a signature check: the prologue bytes, plus the relocated `a3 <&DAT_01faa10c>` at +0x20. The check runs on the first client `sendto` and logs `game socket fix available`. It was verified armed at runtime but never triggered.

## Problems and fixes

1. **The server needs `/lan`**, as in BF1. Without it, the autonet path calls the Galaxy branch (`FUN_005a2150`) and UDP 3656/3658 never open.
2. **`/norender` crashes silently in the GOG exe. The proxy fixes it.**
   - **Why it looks like a clean exit:**
     - WinMain's body is wrapped in `__try/__except`. The filter at `0x00618b90` accepts `0xC0000005` (access violation) and `0xC000008E` (FP divide by zero), and the handler at `0x00618bb5` calls `exit(0)`.
     - So any early crash exits with code 0 and leaves no Windows Error Reporting or Event 1000 entry.
   - **The crash:**
     - About 100 ms after start, the texture loader `FUN_006bb440` → `FUN_006bb620` calls `D3DXCheckTextureRequirements(DAT_007f6dec, …)` through IAT slot `0x0076c52c`.
     - Under `/norender`, `DAT_007f6dec` holds a non-null stand-in, not a real device, and d3dx9_43 null-dereferences inside it (`d3dx9_43.dll+c5501`).
     - The plain Direct3D wrappers (`FUN_006b9xxx`) check the norender flag `DAT_01eae932`; this D3DX call doesn't. It is presumably a regression from the re-release, since older dedicated servers used `/norender`.
   - **The fix:**
     - When `/norender` (or `-norender` or `+norender`) is on the command line, the proxy hooks that import and returns `S_OK` with the requested format unchanged.
     - Without `/norender` the hook is not installed.
   - **Result:**
     - The server shows the game's original text-mode status window ("Game: … / Mission: …") and uses about 92 MB and 8 % of one core.
     - A client joined and played a match with no faults on either side.
     - *Unverified:* a map rotation or round end under `/norender`. Every D3DX texture check goes through the same hook, so it should be covered.
   - **How it was found:** two diagnostics are permanent in the proxy and cost nothing in normal use.
     - A vectored exception handler logs the first 10 first-chance access violations and divide-by-zeros. Each entry gives module+offset and a scan of the stack for code addresses.
     - `DLL_PROCESS_DETACH` logs the exiting thread's backtrace.
     - Exe frames are printed as Ghidra VAs.
3. **Broadcast doesn't cross Tailscale, and the game rejects `100.x` addresses.** These are fixed as in BF1:
   - **Client:** `connect`/`sendto` to broadcast:3656 is redirected to the ini's `Server=`.
   - **Server:** records each discovery prober's address for 15 s, and sends every discovery reply by unicast to each recent prober.
   - **Address alias:** a bijective `100.A.B.C` ↔ `10.A.B.C` mapping (100.64.0.0/10 onto 10.64.0.0/10).
     - `recvfrom` rewrites sources to 10.x before the game sees them.
     - `connect`/`sendto` rewrite 10.64/10 destinations back to 100.x.
     - The game never sees a Tailscale address, so its RFC 1918 `int3` never fires.
4. **`/autonet client` joins only a server whose name matches.** It compares its own `/gamename`, or the literal `AUTONET`, with the session name (`FUN_005e5280`, `DAT_007e9edc`). Without `/gamename` it browses forever on a black screen with a **Back** button. That happens without the proxy too. For normal play, use the in-game LAN browser.
5. **Testing a server and a client on one machine:**
   - Both instances bind 3656 with `SO_REUSEADDR`, so a unicast reply can land in the server's own socket.
   - The test-only ini key `TestDiscoveryReplyPort=3657` fixes this. It must be set on **both** sides: the client binds its discovery receive socket to 3657, and the server replies there.
   - Point the client's `Server=` at the machine's own Tailscale IP.
   - Leave the key out for real deployments.
6. **High in-game ping with the default tick rate.** The dedicated server's default `/tps` is 20, so 50 ms per tick. Over a 16–20 ms Tailscale path, the game showed 90–100 ms ping. The example batch file uses `/tps 60`; the resulting ping is *unverified*.

## Dedicated-server switches

These come from the parser `FUN_00479740` and the `.data` defaults.

| Switch | Hash | Global | Default | Notes |
|---|---|---|---|---|
| `/lan` | 56608010 | `DAT_01eae930` | 0 | Required for LAN |
| `/autonet dedicated\|client\|host` | C23937B9 | `DAT_01e6650f`, string `DAT_01eae934` | | |
| `/gamename X` | 4F0C4904 | `DAT_007e9e98` | | Also used by `/autonet client` to choose a server |
| `/playercount N` | C707B50F | `DAT_007e9e90` | **2** | The server waits ("Waiting for players…") until N players have joined |
| `/playerlimit N` | 3A00D703 | `DAT_007e926c` (+2 copies) | 64 | |
| `/bots N` | E181E077 | `DAT_007e8f50` (+many copies, one per mode) | −1 (mission default) | |
| `/tps N` | B22236AE | `DAT_007e9e94` | **20** | Network tick. **`/tps 0` executes `int3`.** Passed to `FUN_005b9740(rate,1)` and sent to clients as a 10-bit field (`FUN_005e7060`, `FUN_005dcdd0`). Values below 10 fall back to the default. A menu host uses its profile byte `+0x6cd` instead. |
| `/throttle N` | 378F32DD | `DAT_01eae918` | 0 | If nonzero, it sets the upload budget (`FUN_005dc000`) |
| `/netplayers N` | 90B89FFA | `DAT_01eae920` | 0 | Used only in non-LAN mode |
| `/skill N` | CA15D036 | `DAT_007ea030` | 2 | Clamped to 1..3 |
| `/sideselect` | 99317EA6 | `DAT_007e902d` (auto-assign), `DAT_01ed7e17` := 0 | | Players pick and switch sides |
| `/noteamdamage` | E51023BA | `DAT_007e902f` := 0 | on | |
| `/nonames` | C11F80F6 | `DAT_007e9e50` := 0 | on | |
| `/heroes N` | A8C4C105 | `DAT_007e837c` = N≠0 | on | |
| `/password X` | 364B5F18 | `DAT_01e31c40`, hash `DAT_01eae958` | | Matches the config-file "password" key, so probably the join password. Untested. |
| `/adminpw X` | 03D17781 | `DAT_01e64330` | | Up to 15 characters |
| `/norender` | 75E8450E | `DAT_01eae932` | | Works **only with the proxy** (problem 2) |
| `/nosound` `/win` `/resolution W H` | F4553EF1 / 0BF7CB59 / 1D215C8F | | | |
| `/bandwidth` `/latency` `/loss` `/jitter` | 91739772 / F2FB8359 / E7347B1A / 02049853 | set `DAT_01e58ebf`=1 | | Network **simulator**, i.e. fake lag. Don't use. |
| `/connect` `/name` | AAE0CCF9 / 8D39BDE6 | | | Feed `ScriptCB_IsCmdlineJoinPending` and `ScriptCB_GetCmdlineLogin`, the old GameSpy Arcade join. Not a working direct-IP path. |

Hero tuning switches, with their defaults: `/hrunlock` 3, `/hrunlockvalue` 10, `/hrplayer` 1, `/hrteam` 3 and `/hrrespawn` 2. Each one also has a second, uncracked alias hash (202DB217, AC16C90C, ECD7701E, F546DAFE and 3EC8DA95 respectively). What the enum values mean is unverified. Also cracked: `/pregametime N` (371E360D), `/voicemode` (DADFA856), and `/nolegal` / `/showlegal`.

A server launched with every option in the example batch file flipped from its default, plus `/tps 60`, `/bots 10`, `/skill 3` and map tickets `150 150`, started and loaded its map. The options' in-game effects have not been checked one by one.

**Bandwidth (different from BF1):** in LAN mode with `/throttle` unset, `FUN_005dc000` sets a fixed upload budget of `0x500000`. BF1's rubberbanding fix (`/netplayers 32`) is therefore not needed. That is *unverified with many bots*. If bots rubberband over Tailscale, try `/throttle`.

Uncracked switch hashes (every value the parser compares against): 09c3e0ff 0652936b 0d3d814f 124e8fbb 1503f968 204f0d0d 1debae35 2264b8ed 26d94b4e 351fc388 31694a02 4eae0006 3c3f5c38 42eaccdd 68f63adb 5d62beb3 6363d774 718e7ad4 8de05c06 8a8753c7 7ac8bb2b 8463e1a0 8ceac9bd 98bf5c17 996359b2 a563005a bbb3b003 ba0ecd59 bc494aff c01e4e25 cd154944 c16650c8 c53b7844 d43981b7 d0bd1109 d5c0b6f5 e0ebca12 e3d8ab51 e91814a3 f5dd1fbd f6976b61.

## Pitfalls to remember

- **Read relocated operands.** With ASLR, absolute operands inside code are relocated too, so signature checks must compare relocated values, not file bytes.
- **A clean exit with code 0 can be a crash.** WinMain's `__except` hides early crashes. Use the proxy's `first-chance exception` and `process exiting` log lines.
- **Firewall:** allow inbound UDP 3656, 3658 and 3659 on both sides. The discovery reply comes from the server's ephemeral port, so the client's outbound probe doesn't open a stateful path for it.
- **Tailscale topology:** Tailscale must run *inside* the server VM. A subnet router on the host is not enough.

## Ghidra headless

Import and analyse the exe once:

```
analyzeHeadless <projdir> <name> -import BattlefrontII.exe
```

Then run the scripts read-only:

```
analyzeHeadless <projdir> <name> -process BattlefrontII.exe -noanalysis -readOnly -scriptPath ghidra_scripts -postScript DecompileAt.java nocallers 0x00618db0
```

`nocallers` affects only the addresses that follow it.
