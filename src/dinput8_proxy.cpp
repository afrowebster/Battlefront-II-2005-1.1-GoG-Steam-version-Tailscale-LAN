// Battlefront II (2005) Tailscale LAN proxy
// Port of the Battlefront (2004) proxy:
// https://github.com/afrowebster/Battlefront-2004-1.3.7-GoG-Steam-version-Tailscale-LAN
// Copyright (C) 2026 afrowebster
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version. It is distributed WITHOUT ANY WARRANTY; see the LICENSE
// file or <https://www.gnu.org/licenses/>.

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <dinput.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>

using DirectInput8CreateFn = HRESULT(WINAPI *)(HINSTANCE, DWORD, REFIID, LPVOID *, LPUNKNOWN);
using BindFn = int(WSAAPI *)(SOCKET, const sockaddr *, int);
using CloseSocketFn = int(WSAAPI *)(SOCKET);
using ConnectFn = int(WSAAPI *)(SOCKET, const sockaddr *, int);
using RecvFromFn = int(WSAAPI *)(SOCKET, char *, int, int, sockaddr *, int *);
using SendFn = int(WSAAPI *)(SOCKET, const char *, int, int);
using SendToFn = int(WSAAPI *)(SOCKET, const char *, int, int, const sockaddr *, int);

enum class ProxyMode {
    None,
    Client,
    Server
};

// BF2 discovery: a UDP socket connect()ed to 255.255.255.255:3656 with SO_BROADCAST
// sends probes (client) and replies (server); a second socket bound to 0.0.0.0:3656
// receives them (FUN_00618c80). Session traffic uses DAT_01faa10c, bound to 3658 by
// a host and 3659 by a client (FUN_00618db0).
static const u_short kDiscoveryPort = 3656;

// Test-only (TestDiscoveryReplyPort= in the ini): when a server and a client run on
// one machine, both bind 3656 with SO_REUSEADDR and a unicast reply may land in the
// server's own socket. The client then binds its discovery receive socket to this
// port instead, and the server sends replies there. Default 3656 = normal behaviour.
static u_short gReplyPort = kDiscoveryPort;

static HMODULE gSystemDinput8;
static DirectInput8CreateFn gDirectInput8Create;
static BindFn gBind;
static CloseSocketFn gCloseSocket;
static ConnectFn gConnect;
static RecvFromFn gRecvFrom;
static SendFn gSend;
static SendToFn gSendTo;
static ProxyMode gMode = ProxyMode::None;
static in_addr gServerAddress;
static volatile SOCKET gDiscoverySendSocket = INVALID_SOCKET;
static volatile SOCKET gDiscoveryReceiveSocket = INVALID_SOCKET;
static CRITICAL_SECTION gPeerLock;
static sockaddr_in gPeers[32];
static DWORD gPeerSeen[32];
static volatile LONG gInitialized;

static CRITICAL_SECTION gLogLock;
static HANDLE gLogFile = INVALID_HANDLE_VALUE;
static LONG gLogBytes;
static const LONG kLogLimit = 4 * 1024 * 1024;

static void Log(const char *format, ...) {
    if (gLogFile == INVALID_HANDLE_VALUE) {
        return;
    }

    char line[512];
    SYSTEMTIME time;
    GetLocalTime(&time);
    int length = std::snprintf(line, sizeof(line), "%02u:%02u:%02u.%03u ", time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);

    va_list arguments;
    va_start(arguments, format);
    const int written = std::vsnprintf(line + length, sizeof(line) - length - 2, format, arguments);
    va_end(arguments);
    if (written > 0) {
        length += (written < static_cast<int>(sizeof(line)) - length - 2) ? written : static_cast<int>(sizeof(line)) - length - 3;
    }
    line[length++] = '\r';
    line[length++] = '\n';

    EnterCriticalSection(&gLogLock);
    if (gLogBytes < kLogLimit) {
        DWORD ignored;
        WriteFile(gLogFile, line, length, &ignored, nullptr);
        gLogBytes += length;
    }
    LeaveCriticalSection(&gLogLock);
}

static const char *FormatAddress(const sockaddr *address, int length, char *output, size_t capacity) {
    if (address == nullptr || length < static_cast<int>(sizeof(sockaddr_in)) || address->sa_family != AF_INET) {
        std::snprintf(output, capacity, "<non-ipv4>");
        return output;
    }

    const auto *ipv4 = reinterpret_cast<const sockaddr_in *>(address);
    const auto *bytes = reinterpret_cast<const unsigned char *>(&ipv4->sin_addr.s_addr);
    std::snprintf(output, capacity, "%u.%u.%u.%u:%u", bytes[0], bytes[1], bytes[2], bytes[3], ntohs(ipv4->sin_port));
    return output;
}

static bool IsIpv4(const sockaddr *address, int length) {
    return address != nullptr && length >= static_cast<int>(sizeof(sockaddr_in)) && address->sa_family == AF_INET;
}

static bool IsDiscoveryAddress(const sockaddr *address, int length) {
    if (!IsIpv4(address, length)) {
        return false;
    }

    const auto *ipv4 = reinterpret_cast<const sockaddr_in *>(address);
    return ipv4->sin_port == htons(kDiscoveryPort) && ipv4->sin_addr.s_addr == INADDR_BROADCAST;
}

static bool IsTailscaleAddress(const sockaddr *address) {
    if (address == nullptr || address->sa_family != AF_INET) {
        return false;
    }
    const unsigned long host = ntohl(reinterpret_cast<const sockaddr_in *>(address)->sin_addr.s_addr);
    return (host & 0xffc00000UL) == 0x64400000UL;
}

// The game asserts (int3 in FUN_005d77f0 and FUN_005d8820, via the RFC 1918 test
// FUN_005d5a80) that every peer address is private, so Tailscale's 100.64.0.0/10
// is presented to it as 10.64.0.0/10 and mapped back on the way out:
// 100.A.B.C <-> 10.A.B.C.
static bool IsMappedAddress(unsigned long host) {
    return (host & 0xffc00000UL) == 0x0a400000UL;
}

static void ToGameAddress(sockaddr *address) {
    if (!IsTailscaleAddress(address)) {
        return;
    }
    auto *ipv4 = reinterpret_cast<sockaddr_in *>(address);
    ipv4->sin_addr.s_addr = htonl((ntohl(ipv4->sin_addr.s_addr) & 0x00ffffffUL) | 0x0a000000UL);
}

// Returns true and fills output when the destination is a mapped address.
static bool ToWireAddress(const sockaddr *address, int length, sockaddr_in &output) {
    if (!IsIpv4(address, length)) {
        return false;
    }
    output = *reinterpret_cast<const sockaddr_in *>(address);
    const unsigned long host = ntohl(output.sin_addr.s_addr);
    if (!IsMappedAddress(host)) {
        return false;
    }
    output.sin_addr.s_addr = htonl((host & 0x00ffffffUL) | 0x64000000UL);
    return true;
}

static void FormatHex(const char *buffer, int length, char *output, size_t capacity, int limit = 16) {
    size_t used = 0;
    output[0] = '\0';
    for (int index = 0; index < length && index < limit && used + 4 < capacity; ++index) {
        used += std::snprintf(output + used, capacity - used, "%02x ", static_cast<unsigned char>(buffer[index]));
    }
}

// BF2's discovery packet layout is not known yet, so discovery traffic is
// identified by socket and the first packets are dumped to learn it.
static void LogDiscoveryPacket(const char *what, SOCKET socket, const char *buffer, int length, const char *peer) {
    static volatile LONG logged;
    if (InterlockedIncrement(&logged) > 200) {
        return;
    }
    char hex[200];
    FormatHex(buffer, length, hex, sizeof(hex), 64);
    Log("%s socket=%u (%d bytes) %s: %s", what, static_cast<unsigned>(socket), length, peer, hex);
}

static void RecordPeer(const sockaddr_in &source) {
    sockaddr_in peer = source;
    peer.sin_port = htons(gReplyPort);
    const DWORD now = GetTickCount();

    EnterCriticalSection(&gPeerLock);
    int slot = -1;
    int oldest = 0;
    for (int index = 0; index < 32; ++index) {
        if (gPeerSeen[index] != 0 && gPeers[index].sin_addr.s_addr == peer.sin_addr.s_addr) {
            slot = index;
            break;
        }
        if (gPeerSeen[index] == 0) {
            slot = index;
            break;
        }
        if (gPeerSeen[index] < gPeerSeen[oldest]) {
            oldest = index;
        }
    }

    if (slot < 0) {
        slot = oldest;
    }

    gPeers[slot] = peer;
    gPeerSeen[slot] = now;
    LeaveCriticalSection(&gPeerLock);
}

static int SnapshotPeers(sockaddr_in *peers, int capacity) {
    const DWORD now = GetTickCount();
    int count = 0;

    EnterCriticalSection(&gPeerLock);
    for (int index = 0; index < 32 && count < capacity; ++index) {
        if (gPeerSeen[index] == 0 || now - gPeerSeen[index] > 15000) {
            gPeerSeen[index] = 0;
            continue;
        }
        peers[count++] = gPeers[index];
    }
    LeaveCriticalSection(&gPeerLock);

    return count;
}

static int WSAAPI HookBind(SOCKET socket, const sockaddr *name, int nameLength) {
    if (gBind == nullptr) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    char text[32];
    if (!IsIpv4(name, nameLength) || reinterpret_cast<const sockaddr_in *>(name)->sin_port != htons(kDiscoveryPort)) {
        const int result = gBind(socket, name, nameLength);
        Log("bind socket=%u to %s result=%d error=%d", static_cast<unsigned>(socket), FormatAddress(name, nameLength, text, sizeof(text)), result, result == SOCKET_ERROR ? WSAGetLastError() : 0);
        return result;
    }

    gDiscoveryReceiveSocket = socket;
    sockaddr_in local = *reinterpret_cast<const sockaddr_in *>(name);
    if (gMode == ProxyMode::Client) {
        local.sin_port = htons(gReplyPort);
    }
    const int result = gBind(socket, reinterpret_cast<const sockaddr *>(&local), sizeof(local));
    Log("bind socket=%u to %s recorded as discovery receive socket result=%d", static_cast<unsigned>(socket), FormatAddress(reinterpret_cast<const sockaddr *>(&local), sizeof(local), text, sizeof(text)), result);
    return result;
}

static int WSAAPI HookCloseSocket(SOCKET socket) {
    if (gCloseSocket == nullptr) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    if (socket == gDiscoverySendSocket) {
        gDiscoverySendSocket = INVALID_SOCKET;
    }
    if (socket == gDiscoveryReceiveSocket) {
        gDiscoveryReceiveSocket = INVALID_SOCKET;
    }
    Log("closesocket socket=%u", static_cast<unsigned>(socket));
    return gCloseSocket(socket);
}

static int WSAAPI HookConnect(SOCKET socket, const sockaddr *name, int nameLength) {
    if (gConnect == nullptr) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    char text[32];
    if (IsDiscoveryAddress(name, nameLength)) {
        gDiscoverySendSocket = socket;
        if (gMode == ProxyMode::Client) {
            sockaddr_in target = *reinterpret_cast<const sockaddr_in *>(name);
            target.sin_addr = gServerAddress;
            const int result = gConnect(socket, reinterpret_cast<const sockaddr *>(&target), sizeof(target));
            Log("connect socket=%u broadcast:%u redirected to %s result=%d error=%d", static_cast<unsigned>(socket), kDiscoveryPort, FormatAddress(reinterpret_cast<const sockaddr *>(&target), sizeof(target), text, sizeof(text)), result, result == SOCKET_ERROR ? WSAGetLastError() : 0);
            return result;
        }
        Log("connect socket=%u to broadcast:%u recorded as discovery send socket", static_cast<unsigned>(socket), kDiscoveryPort);
    }
    else {
        sockaddr_in wire;
        if (ToWireAddress(name, nameLength, wire)) {
            const int result = gConnect(socket, reinterpret_cast<const sockaddr *>(&wire), sizeof(wire));
            Log("connect socket=%u to %s (unmapped from 10.x) result=%d", static_cast<unsigned>(socket), FormatAddress(reinterpret_cast<const sockaddr *>(&wire), sizeof(wire), text, sizeof(text)), result);
            return result;
        }
        Log("connect socket=%u to %s (passthrough)", static_cast<unsigned>(socket), FormatAddress(name, nameLength, text, sizeof(text)));
    }

    return gConnect(socket, name, nameLength);
}

static int WSAAPI HookRecvFrom(SOCKET socket, char *buffer, int length, int flags, sockaddr *from, int *fromLength) {
    if (gRecvFrom == nullptr) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    const int result = gRecvFrom(socket, buffer, length, flags, from, fromLength);
    if (result <= 0 || from == nullptr || fromLength == nullptr) {
        return result;
    }

    char text[32];
    if (socket == gDiscoveryReceiveSocket) {
        LogDiscoveryPacket("recvfrom discovery", socket, buffer, result, FormatAddress(from, *fromLength, text, sizeof(text)));
        if (gMode == ProxyMode::Server && from->sa_family == AF_INET) {
            RecordPeer(*reinterpret_cast<const sockaddr_in *>(from));
        }
    }
    else if (IsTailscaleAddress(from)) {
        static volatile LONG tailscaleLogged;
        if (InterlockedIncrement(&tailscaleLogged) <= 50) {
            char hex[200];
            FormatHex(buffer, result, hex, sizeof(hex), 64);
            Log("recvfrom socket=%u other datagram (%d bytes) from %s: %s", static_cast<unsigned>(socket), result, FormatAddress(from, *fromLength, text, sizeof(text)), hex);
        }
    }

    if (*fromLength >= static_cast<int>(sizeof(sockaddr_in))) {
        ToGameAddress(from);
    }
    return result;
}

// Sends a discovery reply to every recently seen prober instead of broadcasting it.
static int UnicastReply(SOCKET socket, const char *buffer, int length, int flags, bool connected) {
    sockaddr_in peers[32];
    const int peerCount = SnapshotPeers(peers, 32);
    if (peerCount == 0) {
        Log("discovery reply on socket=%u: no recent probers, falling back to original send", static_cast<unsigned>(socket));
        return -2;
    }

    char text[32];
    int result = SOCKET_ERROR;
    for (int index = 0; index < peerCount; ++index) {
        const auto *peer = reinterpret_cast<const sockaddr *>(&peers[index]);
        int sent;
        if (connected) {
            if (gConnect(socket, peer, sizeof(peers[index])) == SOCKET_ERROR) {
                Log("discovery reply: connect to %s failed error=%d", FormatAddress(peer, sizeof(peers[index]), text, sizeof(text)), WSAGetLastError());
                continue;
            }
            sent = gSend(socket, buffer, length, flags);
        }
        else {
            sent = gSendTo(socket, buffer, length, flags, peer, sizeof(peers[index]));
        }
        Log("discovery reply (%d bytes) unicast to %s result=%d error=%d", length, FormatAddress(peer, sizeof(peers[index]), text, sizeof(text)), sent, sent == SOCKET_ERROR ? WSAGetLastError() : 0);
        if (sent != SOCKET_ERROR) {
            result = sent;
        }
    }

    return result;
}

static int WSAAPI HookSend(SOCKET socket, const char *buffer, int length, int flags) {
    if (gSend == nullptr) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    if (socket != gDiscoverySendSocket) {
        return gSend(socket, buffer, length, flags);
    }

    LogDiscoveryPacket("send discovery", socket, buffer, length, gMode == ProxyMode::Server ? "(server reply)" : "(client probe)");
    if (gMode != ProxyMode::Server) {
        return gSend(socket, buffer, length, flags);
    }

    const int result = UnicastReply(socket, buffer, length, flags, true);
    return result == -2 ? gSend(socket, buffer, length, flags) : result;
}

// Battlefront II (GOG, exe SHA-256 9737C82A...5541) game-socket workaround, the same
// teardown race as Battlefront 1: the server browser's stop paths (FUN_005d6ef0,
// FUN_005d7020) close the session socket through FUN_00618ea0 and zero it, guarded
// only by DAT_01e664e8 != 2, which is never 2. If that runs after a join started,
// every join packet goes to socket 0. Reopen it through the game's own FUN_00618db0.
static const ULONG_PTR kImageBase = 0x00400000;
static const ULONG_PTR kOpenGameSocket = 0x00618db0;   // __fastcall(char host): socket()+bind(3658 host / 3659 client), stores DAT_01faa10c, returns port
static const ULONG_PTR kGameSocket = 0x01faa10c;       // session UDP socket
static const ULONG_PTR kGameSocketOpen = 0x01e64328;   // "session socket open" (holds the port)

static int gGameSocketFixState;   // 0 = not checked yet, 1 = available, -1 = unavailable

static void *GameAddress(ULONG_PTR address) {
    return reinterpret_cast<unsigned char *>(GetModuleHandleW(nullptr)) + (address - kImageBase);
}

// Checked lazily: the executable's code may not be in its final state while DllMain runs.
static bool GameSocketFixAvailable() {
    if (gGameSocketFixState != 0) {
        return gGameSocketFixState > 0;
    }

    // push ebp; mov ebp,esp; and esp,-8; sub esp,1c; push ebx/esi/edi; push 11; push 2; push 2; mov bl,cl; call [socket]
    static const unsigned char prologue[] = { 0x55, 0x8b, 0xec, 0x83, 0xe4, 0xf8, 0x83, 0xec, 0x1c, 0x53, 0x56, 0x57, 0x6a, 0x11, 0x6a, 0x02, 0x6a, 0x02, 0x8a, 0xd9, 0xff, 0x15 };
    // The executable is relocatable, so the store's operand holds the relocated
    // address of DAT_01faa10c (mov [DAT_01faa10c], eax = a3 <address> at +0x20).
    const auto *code = static_cast<const unsigned char *>(GameAddress(kOpenGameSocket));
    const ULONG_PTR expectedStore = reinterpret_cast<ULONG_PTR>(GameAddress(kGameSocket));
    ULONG_PTR actualStore;
    std::memcpy(&actualStore, code + 0x21, sizeof(actualStore));
    const bool matched = std::memcmp(code, prologue, sizeof(prologue)) == 0 && code[0x20] == 0xa3 && actualStore == expectedStore;
    gGameSocketFixState = matched ? 1 : -1;

    char hex[100];
    FormatHex(reinterpret_cast<const char *>(code), 24, hex, sizeof(hex), 24);
    char storeHex[32];
    FormatHex(reinterpret_cast<const char *>(code + 0x20), 5, storeHex, sizeof(storeHex));
    Log("game socket fix %s: module base=%p code=%s| +20=%s", matched ? "available" : "UNAVAILABLE", GetModuleHandleW(nullptr), hex, storeHex);
    return matched;
}

static SOCKET ReopenGameSocket() {
    if (!GameSocketFixAvailable()) {
        return 0;
    }
    auto *gameSocket = static_cast<volatile SOCKET *>(GameAddress(kGameSocket));
    if (*gameSocket != 0) {
        return *gameSocket;
    }

    using OpenGameSocketFn = int(__fastcall *)(char);
    const int port = reinterpret_cast<OpenGameSocketFn>(GameAddress(kOpenGameSocket))(0);
    *static_cast<volatile int *>(GameAddress(kGameSocketOpen)) = port;
    Log("game session socket was closed during join; reopened as socket=%u port=%d", static_cast<unsigned>(*gameSocket), port);
    return *gameSocket;
}

static int WSAAPI HookSendTo(SOCKET socket, const char *buffer, int length, int flags, const sockaddr *to, int toLength) {
    if (gSendTo == nullptr) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    // Run the signature check once early so every log shows whether the fix is armed.
    if (gGameSocketFixState == 0 && gMode == ProxyMode::Client) {
        GameSocketFixAvailable();
    }

    if (socket == 0 && gMode == ProxyMode::Client) {
        const SOCKET reopened = ReopenGameSocket();
        if (reopened != 0) {
            socket = reopened;
        }
    }

    if (!IsDiscoveryAddress(to, toLength)) {
        sockaddr_in wire;
        if (ToWireAddress(to, toLength, wire)) {
            static volatile LONG mappedLogged;
            const int result = gSendTo(socket, buffer, length, flags, reinterpret_cast<const sockaddr *>(&wire), sizeof(wire));
            if (InterlockedIncrement(&mappedLogged) <= 50) {
                char text[32];
                char hex[200];
                FormatHex(buffer, length, hex, sizeof(hex), 64);
                Log("sendto socket=%u (%d bytes) to %s (unmapped from 10.x) result=%d error=%d: %s", static_cast<unsigned>(socket), length, FormatAddress(reinterpret_cast<const sockaddr *>(&wire), sizeof(wire), text, sizeof(text)), result, result == SOCKET_ERROR ? WSAGetLastError() : 0, hex);
            }
            return result;
        }
        return gSendTo(socket, buffer, length, flags, to, toLength);
    }

    if (gMode == ProxyMode::Client) {
        sockaddr_in target = *reinterpret_cast<const sockaddr_in *>(to);
        target.sin_addr = gServerAddress;
        const int result = gSendTo(socket, buffer, length, flags, reinterpret_cast<const sockaddr *>(&target), sizeof(target));
        char text[32];
        Log("sendto socket=%u broadcast:%u (%d bytes) redirected to %s result=%d", static_cast<unsigned>(socket), kDiscoveryPort, length, FormatAddress(reinterpret_cast<const sockaddr *>(&target), sizeof(target), text, sizeof(text)), result);
        return result;
    }

    if (gMode == ProxyMode::Server) {
        const int result = UnicastReply(socket, buffer, length, flags, false);
        if (result != -2) {
            return result;
        }
    }

    Log("sendto socket=%u broadcast:%u (%d bytes) passthrough", static_cast<unsigned>(socket), kDiscoveryPort, length);
    return gSendTo(socket, buffer, length, flags, to, toLength);
}

static bool GetGameDirectory(char *output, size_t capacity) {
    if (GetModuleFileNameA(nullptr, output, static_cast<DWORD>(capacity)) == 0) {
        return false;
    }

    char *separator = std::strrchr(output, '\\');
    if (separator == nullptr) {
        return false;
    }
    *separator = '\0';
    return true;
}

static void OpenLog(const char *directory) {
    char logPath[MAX_PATH];
    std::snprintf(logPath, sizeof(logPath), "%s\\BattlefrontIIDirectIp.log", directory);
    gLogFile = CreateFileA(logPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

static bool Configure(const char *iniPath) {
    const UINT replyPort = GetPrivateProfileIntA("BattlefrontIIDirectIp", "TestDiscoveryReplyPort", kDiscoveryPort, iniPath);
    if (replyPort != 0 && replyPort <= 0xffff) {
        gReplyPort = static_cast<u_short>(replyPort);
    }
    if (gReplyPort != kDiscoveryPort) {
        Log("TestDiscoveryReplyPort=%u (single-machine testing only)", gReplyPort);
    }

    char mode[16];
    GetPrivateProfileStringA("BattlefrontIIDirectIp", "Mode", "", mode, sizeof(mode), iniPath);
    if (_stricmp(mode, "client") == 0) {
        char server[64];
        GetPrivateProfileStringA("BattlefrontIIDirectIp", "Server", "", server, sizeof(server), iniPath);
        const unsigned long address = inet_addr(server);
        if (address != INADDR_NONE && address != INADDR_ANY) {
            gServerAddress.s_addr = address;
            gMode = ProxyMode::Client;
            Log("mode=client server=%s", server);
            return true;
        }
        Log("mode=client but Server='%s' is not a valid IPv4 address", server);
        return false;
    }

    if (_stricmp(mode, "server") == 0) {
        gMode = ProxyMode::Server;
        Log("mode=server");
        return true;
    }

    Log("Mode='%s' not recognised (expected client or server); proxy inactive", mode);
    return false;
}

static void PatchImport(IMAGE_THUNK_DATA32 *entry, FARPROC replacement) {
    DWORD originalProtection;
    if (!VirtualProtect(&entry->u1.Function, sizeof(entry->u1.Function), PAGE_READWRITE, &originalProtection)) {
        Log("VirtualProtect failed error=%lu", GetLastError());
        return;
    }
    entry->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);
    VirtualProtect(&entry->u1.Function, sizeof(entry->u1.Function), originalProtection, &originalProtection);
}

static bool PatchWinsockImports() {
    auto *base = reinterpret_cast<unsigned char *>(GetModuleHandleW(nullptr));
    auto *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    auto *nt = reinterpret_cast<IMAGE_NT_HEADERS32 *>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    const auto &directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (directory.VirtualAddress == 0) {
        return false;
    }

    auto *descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(base + directory.VirtualAddress);
    for (; descriptor->Name != 0; ++descriptor) {
        const char *moduleName = reinterpret_cast<const char *>(base + descriptor->Name);
        if (_stricmp(moduleName, "WS2_32.DLL") != 0) {
            continue;
        }

        // BattlefrontII.exe imports Winsock by ordinal, so match IAT entries by the
        // resolved export address rather than by import name.
        const HMODULE winsock = GetModuleHandleA("ws2_32.dll");
        if (winsock == nullptr) {
            Log("ws2_32.dll not loaded");
            return false;
        }
        const ULONG_PTR bindAddress = reinterpret_cast<ULONG_PTR>(GetProcAddress(winsock, "bind"));
        const ULONG_PTR closeSocketAddress = reinterpret_cast<ULONG_PTR>(GetProcAddress(winsock, "closesocket"));
        const ULONG_PTR connectAddress = reinterpret_cast<ULONG_PTR>(GetProcAddress(winsock, "connect"));
        const ULONG_PTR recvFromAddress = reinterpret_cast<ULONG_PTR>(GetProcAddress(winsock, "recvfrom"));
        const ULONG_PTR sendAddress = reinterpret_cast<ULONG_PTR>(GetProcAddress(winsock, "send"));
        const ULONG_PTR sendToAddress = reinterpret_cast<ULONG_PTR>(GetProcAddress(winsock, "sendto"));

        auto *entries = reinterpret_cast<IMAGE_THUNK_DATA32 *>(base + descriptor->FirstThunk);
        for (; entries->u1.Function != 0; ++entries) {
            const ULONG_PTR function = entries->u1.Function;
            if (function == bindAddress) {
                gBind = reinterpret_cast<BindFn>(function);
                PatchImport(entries, reinterpret_cast<FARPROC>(HookBind));
            }
            else if (function == closeSocketAddress) {
                gCloseSocket = reinterpret_cast<CloseSocketFn>(function);
                PatchImport(entries, reinterpret_cast<FARPROC>(HookCloseSocket));
            }
            else if (function == connectAddress) {
                gConnect = reinterpret_cast<ConnectFn>(function);
                PatchImport(entries, reinterpret_cast<FARPROC>(HookConnect));
            }
            else if (function == recvFromAddress) {
                gRecvFrom = reinterpret_cast<RecvFromFn>(function);
                PatchImport(entries, reinterpret_cast<FARPROC>(HookRecvFrom));
            }
            else if (function == sendAddress) {
                gSend = reinterpret_cast<SendFn>(function);
                PatchImport(entries, reinterpret_cast<FARPROC>(HookSend));
            }
            else if (function == sendToAddress) {
                gSendTo = reinterpret_cast<SendToFn>(function);
                PatchImport(entries, reinterpret_cast<FARPROC>(HookSendTo));
            }
        }

        Log("hooks: bind=%d closesocket=%d connect=%d recvfrom=%d send=%d sendto=%d", gBind != nullptr, gCloseSocket != nullptr, gConnect != nullptr, gRecvFrom != nullptr, gSend != nullptr, gSendTo != nullptr);
        return gBind != nullptr && gCloseSocket != nullptr && gConnect != nullptr && gRecvFrom != nullptr && gSend != nullptr && gSendTo != nullptr;
    }

    Log("WS2_32.DLL import descriptor not found");
    return false;
}

// /norender fix. With /norender the game has no real Direct3D device (DAT_007f6dec
// holds a stand-in object), but the texture loader FUN_006bb440 -> FUN_006bb620
// still asks D3DX to validate texture formats with it. d3dx9_43 dereferences a null
// inside it, and WinMain's __except (filter 0x00618b90) turns the access violation
// into a silent exit(0) about 100 ms after start. Without rendering there is
// nothing to validate, so accept the requested format as is.
using CheckTextureRequirementsFn = HRESULT(WINAPI *)(void *, UINT *, UINT *, UINT *, DWORD, DWORD *, DWORD);
static CheckTextureRequirementsFn gCheckTextureRequirements;
static bool gNoRender;

static HRESULT WINAPI HookCheckTextureRequirements(void *device, UINT *width, UINT *height, UINT *mipLevels, DWORD usage, DWORD *format, DWORD pool) {
    if (gNoRender || device == nullptr) {
        static volatile LONG logged;
        if (InterlockedIncrement(&logged) == 1) {
            Log("norender fix: D3DXCheckTextureRequirements skipped (device=%p), requested format kept", device);
        }
        return S_OK;
    }
    return gCheckTextureRequirements(device, width, height, mipLevels, usage, format, pool);
}

// The game matches switches case-insensitively after a '/', '-' or '+' prefix.
static bool HasSwitch(const char *name) {
    const char *commandLine = GetCommandLineA();
    const size_t length = std::strlen(name);
    for (const char *cursor = commandLine; *cursor != '\0'; ++cursor) {
        const bool atStart = cursor == commandLine || cursor[-1] == ' ' || cursor[-1] == '\t' || cursor[-1] == '"';
        if (atStart && (*cursor == '/' || *cursor == '-' || *cursor == '+') && _strnicmp(cursor + 1, name, length) == 0 &&
            (cursor[1 + length] == '\0' || cursor[1 + length] == ' ' || cursor[1 + length] == '\t' || cursor[1 + length] == '"')) {
            return true;
        }
    }
    return false;
}

static void PatchNoRenderImports() {
    gNoRender = HasSwitch("norender");
    if (!gNoRender) {
        return;
    }
    auto *base = reinterpret_cast<unsigned char *>(GetModuleHandleW(nullptr));
    auto *nt = reinterpret_cast<IMAGE_NT_HEADERS32 *>(base + reinterpret_cast<IMAGE_DOS_HEADER *>(base)->e_lfanew);
    const auto &directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    const HMODULE d3dx = GetModuleHandleA("d3dx9_43.dll");
    if (directory.VirtualAddress == 0 || d3dx == nullptr) {
        Log("norender fix: d3dx9_43.dll not loaded");
        return;
    }
    const ULONG_PTR target = reinterpret_cast<ULONG_PTR>(GetProcAddress(d3dx, "D3DXCheckTextureRequirements"));
    auto *descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(base + directory.VirtualAddress);
    for (; descriptor->Name != 0; ++descriptor) {
        if (_stricmp(reinterpret_cast<const char *>(base + descriptor->Name), "d3dx9_43.dll") != 0) {
            continue;
        }
        for (auto *entry = reinterpret_cast<IMAGE_THUNK_DATA32 *>(base + descriptor->FirstThunk); entry->u1.Function != 0; ++entry) {
            if (entry->u1.Function == target) {
                gCheckTextureRequirements = reinterpret_cast<CheckTextureRequirementsFn>(entry->u1.Function);
                PatchImport(entry, reinterpret_cast<FARPROC>(HookCheckTextureRequirements));
            }
        }
    }
    Log("norender fix: D3DXCheckTextureRequirements hook=%d", gCheckTextureRequirements != nullptr);
}

// Runs from DllMain: the executable's imports are already bound by then, and a
// /norender dedicated server may never call DirectInput8Create at all.
static void InitializeProxy() {
    if (InterlockedCompareExchange(&gInitialized, 1, 0) != 0) {
        return;
    }

    InitializeCriticalSection(&gPeerLock);
    InitializeCriticalSection(&gLogLock);

    char directory[MAX_PATH];
    if (!GetGameDirectory(directory, sizeof(directory))) {
        return;
    }
    OpenLog(directory);
    Log("BattlefrontIIDirectIp proxy loaded in %s, module base=%p", directory, GetModuleHandleW(nullptr));
    Log("command line: %s", GetCommandLineA());
    PatchNoRenderImports();

    char iniPath[MAX_PATH];
    std::snprintf(iniPath, sizeof(iniPath), "%s\\BattlefrontIIDirectIp.ini", directory);
    if (!Configure(iniPath)) {
        return;
    }

    if (!PatchWinsockImports()) {
        Log("Winsock import patch failed; proxy inactive");
        gMode = ProxyMode::None;
        return;
    }
    Log("proxy active");
}

static bool LoadSystemDirectInput() {
    if (gDirectInput8Create != nullptr) {
        return true;
    }

    char path[MAX_PATH];
    const UINT length = GetSystemDirectoryA(path, MAX_PATH);
    if (length == 0 || length + 13 >= MAX_PATH) {
        return false;
    }
    std::strcat(path, "\\dinput8.dll");

    gSystemDinput8 = LoadLibraryA(path);
    if (gSystemDinput8 == nullptr) {
        return false;
    }

    gDirectInput8Create = reinterpret_cast<DirectInput8CreateFn>(GetProcAddress(gSystemDinput8, "DirectInput8Create"));
    return gDirectInput8Create != nullptr;
}

extern "C" HRESULT WINAPI DirectInput8Create(HINSTANCE instance, DWORD version, REFIID interfaceId, LPVOID *output, LPUNKNOWN outer) {
    if (!LoadSystemDirectInput()) {
        Log("DirectInput8Create: failed to load system dinput8.dll");
        return E_FAIL;
    }

    const HRESULT result = gDirectInput8Create(instance, version, interfaceId, output, outer);
    Log("DirectInput8Create forwarded hr=0x%08lx", static_cast<unsigned long>(result));
    return result;
}

// WinMain runs inside __try/__except (filter at 0x00618b90) that turns an access
// violation or FP divide-by-zero into a silent exit(0). A first-chance vectored
// handler sees the fault before that, so the log shows where it happened.
// "module+offset", or "BattlefrontII.exe ghidra=<VA>" for the executable.
static bool FormatCodeAddress(ULONG_PTR address, char *output, size_t capacity) {
    HMODULE owner = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCSTR>(address), &owner) || owner == nullptr) {
        return false;
    }
    char name[MAX_PATH];
    GetModuleFileNameA(owner, name, sizeof(name));
    const char *shortName = std::strrchr(name, '\\') != nullptr ? std::strrchr(name, '\\') + 1 : name;
    const auto base = reinterpret_cast<ULONG_PTR>(owner);
    if (owner == GetModuleHandleW(nullptr)) {
        std::snprintf(output, capacity, "%s ghidra=%08lx", shortName, static_cast<unsigned long>(address - base + kImageBase));
    }
    else {
        std::snprintf(output, capacity, "%s+%lx", shortName, static_cast<unsigned long>(address - base));
    }
    return true;
}

static LONG CALLBACK LogFault(EXCEPTION_POINTERS *info) {
    const DWORD code = info->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_FLT_DIVIDE_BY_ZERO && code != EXCEPTION_INT_DIVIDE_BY_ZERO) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    static volatile LONG logged;
    if (InterlockedIncrement(&logged) > 10) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const auto address = reinterpret_cast<ULONG_PTR>(info->ExceptionRecord->ExceptionAddress);
    const CONTEXT *context = info->ContextRecord;
    const ULONG_PTR target = info->ExceptionRecord->NumberParameters >= 2 ? info->ExceptionRecord->ExceptionInformation[1] : 0;
    char where[MAX_PATH + 32] = "?";
    FormatCodeAddress(address, where, sizeof(where));
    Log("first-chance exception 0x%08lx at %p (%s) target=%p eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx esi=%08lx edi=%08lx esp=%08lx ebp=%08lx",
        code, info->ExceptionRecord->ExceptionAddress, where, reinterpret_cast<void *>(target),
        context->Eax, context->Ebx, context->Ecx, context->Edx, context->Esi, context->Edi, context->Esp, context->Ebp);
    // Values on the stack that point into a loaded module are likely return addresses.
    const auto *stack = reinterpret_cast<const ULONG_PTR *>(context->Esp);
    int shown = 0;
    for (int index = 0; index < 512 && shown < 24; ++index) {
        MEMORY_BASIC_INFORMATION memory;
        if (VirtualQuery(&stack[index], &memory, sizeof(memory)) == 0 || memory.State != MEM_COMMIT) {
            break;
        }
        const ULONG_PTR value = stack[index];
        if (value < 0x10000 || VirtualQuery(reinterpret_cast<void *>(value), &memory, sizeof(memory)) == 0 || memory.Type != MEM_IMAGE ||
            (memory.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) == 0) {
            continue;
        }
        char text[MAX_PATH + 32];
        if (FormatCodeAddress(value, text, sizeof(text))) {
            Log("  stack[%03d] %s", index, text);
            ++shown;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// On process exit, DllMain runs on the thread that called ExitProcess with its stack
// intact, so log who ended the game. Exe frames are printed as Ghidra VAs.
static void LogExitStack() {
    void *frames[48];
    const USHORT count = CaptureStackBackTrace(0, 48, frames, nullptr);
    const auto exeBase = reinterpret_cast<ULONG_PTR>(GetModuleHandleW(nullptr));
    Log("process exiting; stack of the exiting thread (%u frames):", count);
    for (USHORT index = 0; index < count; ++index) {
        HMODULE owner = nullptr;
        char name[MAX_PATH] = "?";
        const auto address = reinterpret_cast<ULONG_PTR>(frames[index]);
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, static_cast<LPCSTR>(frames[index]), &owner) && owner != nullptr) {
            GetModuleFileNameA(owner, name, sizeof(name));
        }
        const char *shortName = std::strrchr(name, '\\') != nullptr ? std::strrchr(name, '\\') + 1 : name;
        if (reinterpret_cast<ULONG_PTR>(owner) == exeBase) {
            Log("  #%02u %s ghidra=%08lx", index, shortName, static_cast<unsigned long>(address - exeBase + kImageBase));
        }
        else {
            Log("  #%02u %s+%lx", index, shortName, static_cast<unsigned long>(address - reinterpret_cast<ULONG_PTR>(owner)));
        }
    }
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        InitializeProxy();
        AddVectoredExceptionHandler(1, LogFault);
    }
    else if (reason == DLL_PROCESS_DETACH && reserved != nullptr) {
        LogExitStack();
    }
    return TRUE;
}
