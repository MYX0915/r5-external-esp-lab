// kmapctl.exe — kmap.sys 的用户态控制端
// 用法:
//   kmapctl load   <kmap.sys 路径>        安装并启动驱动服务
//   kmapctl unload                        停止并删除服务
//   kmapctl ping                         探活
//   kmapctl inject <pid> <dll> [maponly] 零句柄手动映射 DLL（maponly=只映射不执行）
//   kmapctl base   <pid> <module>        查询目标模块基址
//   kmapctl read   <pid> <hexaddr> <len> 读内存
//   kmapctl write  <pid> <hexaddr> <hex> 写内存
#include <windows.h>
#include <winternl.h>
#include <winsvc.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

#define KMAP_IOCTL_PING    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KMAP_IOCTL_INJECT  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KMAP_IOCTL_READ    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KMAP_IOCTL_WRITE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KMAP_IOCTL_GETBASE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define KMAP_DEVICE L"\\\\.\\KmapDrv"
#define KMAP_SERVICE L"KmapDrv"

#define KMAP_MAX_TIDS 256

struct KMAP_INJECT_REQ
{
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG Flags;
    ULONG ThreadCount;
    WCHAR DllPath[512];
    ULONG ThreadIds[KMAP_MAX_TIDS];
};

struct KMAP_IO_REQ
{
    ULONG ProcessId;
    ULONG Length;
    unsigned long long Address;
    unsigned char Data[1];
};

struct KMAP_BASE_REQ
{
    ULONG ProcessId;
    WCHAR ModuleName[64];
    unsigned long long Base;
    ULONG ImageSize;
};

static HANDLE OpenDevice()
{
    HANDLE h = CreateFileW(KMAP_DEVICE, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        printf("[!] CreateFile(%ls) failed: %lu（驱动未加载或不是管理员）\n", KMAP_DEVICE, GetLastError());
    return h;
}

static bool Ioctl(HANDLE h, DWORD code, void* in, DWORD inLen, DWORD outLen, DWORD* ret)
{
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(h, code, in, inLen, in, outLen, &bytes, nullptr);
    if (ret) *ret = bytes;
    if (!ok) printf("[!] DeviceIoControl 0x%X failed: %lu\n", code, GetLastError());
    return ok != FALSE;
}

static bool InstallDriver(const wchar_t* sysPath)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { printf("[!] OpenSCManager: %lu\n", GetLastError()); return false; }

    SC_HANDLE svc = CreateServiceW(scm, KMAP_SERVICE, KMAP_SERVICE, SERVICE_ALL_ACCESS,
                                   SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                                   sysPath, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc)
    {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_EXISTS)
        {
            svc = OpenServiceW(scm, KMAP_SERVICE, SERVICE_ALL_ACCESS);
        }
        else
        {
            printf("[!] CreateService: %lu\n", e);
            CloseServiceHandle(scm);
            return false;
        }
    }
    if (!svc) { printf("[!] OpenService: %lu\n", GetLastError()); CloseServiceHandle(scm); return false; }

    BOOL ok = StartServiceW(svc, 0, nullptr);
    if (!ok)
    {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_ALREADY_RUNNING) ok = TRUE;
        else printf("[!] StartService: %lu （1814=签名, 577=签名, 1275/1277=加载被拒）\n", e);
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok != FALSE;
}

static bool RemoveDriver()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, KMAP_SERVICE, SERVICE_ALL_ACCESS);
    if (!svc) { CloseServiceHandle(scm); return false; }
    SERVICE_STATUS st{};
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    BOOL ok = DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok != FALSE;
}

static unsigned long long ParseHex(const char* s)
{
    return _strtoui64(s, nullptr, 16);
}

static std::string WideToAnsi(const wchar_t* w)
{
    char buf[512] = {0};
    WideCharToMultiByte(CP_ACP, 0, w, -1, buf, sizeof(buf) - 1, nullptr, nullptr);
    return std::string(buf);
}

// 用 Toolhelp 快照找目标进程的一个线程（不需要 OpenProcess，绕开句柄裁剪）
static DWORD FindFirstThread(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    DWORD tid = 0;
    if (Thread32First(snap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tid;
}

// 取目标进程全部 TID：用户 APC 只在线程可告警等待时交付，所以要广撒网
static std::vector<DWORD> FindAllThreads(DWORD pid, size_t limit)
{
    std::vector<DWORD> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == pid && out.size() < limit)
                out.push_back(te.th32ThreadID);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return out;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2)
    {
        printf("kmapctl load <sys> | unload | ping | inject <pid> <dll> [maponly]\n"
               "        base <pid> <module> | read <pid> <hex> <len> | write <pid> <hex> <hexbytes>\n");
        return 1;
    }

    std::wstring cmd = argv[1];

    if (cmd == L"load")
    {
        if (argc < 3) return 1;
        wchar_t full[MAX_PATH];
        GetFullPathNameW(argv[2], MAX_PATH, full, nullptr);
        printf("[*] install %ls ...\n", full);
        if (!InstallDriver(full)) return 2;
        HANDLE h = OpenDevice();
        if (h == INVALID_HANDLE_VALUE) return 3;
        DWORD got = 0;
        bool ok = Ioctl(h, KMAP_IOCTL_PING, nullptr, 0, 0, &got);
        CloseHandle(h);
        printf(ok ? "[+] driver alive\n" : "[-] ping failed\n");
        return ok ? 0 : 4;
    }
    if (cmd == L"unload")
    {
        printf(RemoveDriver() ? "[+] service deleted\n" : "[-] delete failed\n");
        return 0;
    }

    HANDLE h = OpenDevice();
    if (h == INVALID_HANDLE_VALUE) return 3;

    if (cmd == L"ping")
    {
        DWORD got = 0;
        bool ok = Ioctl(h, KMAP_IOCTL_PING, nullptr, 0, 0, &got);
        printf(ok ? "[+] pong\n" : "[-] no reply\n");
        CloseHandle(h);
        return ok ? 0 : 4;
    }

    if (cmd == L"inject")
    {
        if (argc < 4) { CloseHandle(h); return 1; }
        KMAP_INJECT_REQ req{};
        req.ProcessId = (ULONG)_wtoi(argv[2]);
        req.Flags = 8;   // 默认：调目标 LoadLibraryW（最稳）；其它：maponly / apc / probe / newthread
        if (argc > 4) {
            std::wstring m = argv[4];
            if (m == L"maponly") req.Flags = 1;
            else if (m == L"apc") req.Flags = 0;
            else if (m == L"probe") req.Flags = 6;   // 建线程 + 最小探针壳
            else if (m == L"loadlib") req.Flags = 8; // 默认
            else if (m == L"newthread") req.Flags = 2; // 手动映射 + 建线程
        }

        auto tids = FindAllThreads(req.ProcessId, KMAP_MAX_TIDS);
        if (tids.empty())
        {
            printf("[!] no thread found for pid %lu\n", req.ProcessId);
            CloseHandle(h);
            return 7;
        }
        req.ThreadId = tids[0];
        req.ThreadCount = (ULONG)tids.size();
        for (size_t i = 0; i < tids.size(); i++) req.ThreadIds[i] = tids[i];
        printf("[*] pid=%lu threads=%zu (first tid=%lu)\n", req.ProcessId, tids.size(), req.ThreadId);
        wchar_t full[MAX_PATH];
        GetFullPathNameW(argv[3], MAX_PATH, full, nullptr);
        // 内核 ZwCreateFile 要 NT 路径：DOS 盘符路径必须加 \??\ 前缀，否则 STATUS_OBJECT_PATH_SYNTAX_BAD(161)
        _snwprintf_s(req.DllPath, _countof(req.DllPath), _TRUNCATE, L"\\??\\%s", full);
        if (GetFileAttributesW(full) == INVALID_FILE_ATTRIBUTES)
        {
            printf("[!] dll not found: %ls\n", full);
            CloseHandle(h);
            return 5;
        }
        DWORD got = 0;
        if (!Ioctl(h, KMAP_IOCTL_INJECT, &req, sizeof(req), sizeof(req), &got))
        {
            DWORD e = GetLastError();
            printf("[-] inject failed, last error %lu（STATUS 通过 DeviceIoControl 返回值看：0xC0000xxx）\n", e);
            CloseHandle(h);
            return 6;
        }
        unsigned long long base = 0, shell = 0;
        memcpy(&base, &req, 8);
        memcpy(&shell, (char*)&req + 8, 8);
        printf("[+] mapped at 0x%llX  shell=0x%llX\n", base, shell);
        if (shell && !(req.Flags & 1))
            printf("[*] sentinel @ 0x%llX : 0=shell never ran, 11111111=in entry, 22222222=entry returned\\n", shell + 0x800);
        CloseHandle(h);
        return 0;
    }

    if (cmd == L"base")
    {
        if (argc < 4) { CloseHandle(h); return 1; }
        KMAP_BASE_REQ req{};
        req.ProcessId = (ULONG)_wtoi(argv[2]);
        wcsncpy_s(req.ModuleName, argv[3], _TRUNCATE);
        DWORD got = 0;
        if (!Ioctl(h, KMAP_IOCTL_GETBASE, &req, sizeof(req), sizeof(req), &got))
        {
            CloseHandle(h);
            return 6;
        }
        printf("[+] %ls base = 0x%llX\n", req.ModuleName, req.Base);
        CloseHandle(h);
        return 0;
    }

    if (cmd == L"read")
    {
        if (argc < 5) { CloseHandle(h); return 1; }
        ULONG pid = (ULONG)_wtoi(argv[2]);
        unsigned long long addr = ParseHex(WideToAnsi(argv[3]).c_str());
        ULONG len = (ULONG)_wtoi(argv[4]);
        if (len == 0 || len > 0x100000) len = 256;
        std::vector<unsigned char> buf(sizeof(KMAP_IO_REQ) + len);
        auto req = (KMAP_IO_REQ*)buf.data();
        req->ProcessId = pid; req->Address = addr; req->Length = len;
        DWORD got = 0;
        if (!Ioctl(h, KMAP_IOCTL_READ, req, (DWORD)buf.size(), (DWORD)buf.size(), &got))
        {
            CloseHandle(h);
            return 6;
        }
        for (ULONG i = 0; i < len; i++)
        {
            if (i % 16 == 0) printf("\n%016llX  ", addr + i);
            printf("%02X ", req->Data[i]);
        }
        printf("\n");
        CloseHandle(h);
        return 0;
    }

    if (cmd == L"write")
    {
        if (argc < 5) { CloseHandle(h); return 1; }
        ULONG pid = (ULONG)_wtoi(argv[2]);
        unsigned long long addr = ParseHex(WideToAnsi(argv[3]).c_str());
        std::string hex = WideToAnsi(argv[4]);
        std::vector<unsigned char> data;
        for (size_t i = 0; i + 1 < hex.size();)
        {
            if (hex[i] == ' ' || hex[i] == ',') { i++; continue; }
            data.push_back((unsigned char)strtoul(hex.substr(i, 2).c_str(), nullptr, 16));
            i += 2;
        }
        if (data.empty()) { CloseHandle(h); return 1; }
        std::vector<unsigned char> buf(sizeof(KMAP_IO_REQ) + data.size());
        auto req = (KMAP_IO_REQ*)buf.data();
        req->ProcessId = pid; req->Address = addr; req->Length = (ULONG)data.size();
        memcpy(req->Data, data.data(), data.size());
        DWORD got = 0;
        bool ok = Ioctl(h, KMAP_IOCTL_WRITE, req, (DWORD)buf.size(), (DWORD)buf.size(), &got);
        printf(ok ? "[+] wrote %zu bytes @ 0x%llX\n" : "[-] write failed\n", data.size(), addr);
        CloseHandle(h);
        return ok ? 0 : 6;
    }

    printf("[!] unknown command\n");
    CloseHandle(h);
    return 1;
}
