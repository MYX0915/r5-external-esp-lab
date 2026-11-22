// sc_target.exe -- local dry-run target for sc3.sys
//   * reserves a 0x80000 RW region, keeps the first 12 pages churning (hot)
//     and leaves the rest untouched (stable) -- same shape as a game allocation
//   * runs an alertable-wait thread so a hijackable user context always exists
#include <windows.h>
#include <cstdio>

static PVOID  g_region = nullptr;
static volatile LONG g_stop = 0;

static DWORD WINAPI HotWriter(LPVOID)
{
    unsigned long long tick = 0;
    while (!g_stop) {
        unsigned char* p = (unsigned char*)g_region;
        for (int page = 0; page < 12; page++) {
            for (int i = 0; i < 4096; i += 8)
                *(unsigned long long*)(p + page * 4096 + i) = tick * 0x9E3779B97F4A7C15ull + (unsigned)i;
        }
        tick++;
        Sleep(1);
    }
    return 0;
}

static DWORD WINAPI WaiterThread(LPVOID)
{
    while (!g_stop) SleepEx(200, TRUE);
    return 0;
}

int main()
{
    g_region = VirtualAlloc(nullptr, 0x80000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("[sc_target] pid=%lu region=%p\n", GetCurrentProcessId(), g_region);
    fflush(stdout);
    if (!g_region) return 1;

    // touch every page once so the PTEs are all populated
    for (size_t off = 0; off < 0x80000; off += 4096)
        ((volatile unsigned char*)g_region)[off] = 0;

    HANDLE th[2];
    th[0] = CreateThread(nullptr, 0, HotWriter, nullptr, 0, nullptr);
    th[1] = CreateThread(nullptr, 0, WaiterThread, nullptr, 0, nullptr);
    printf("[sc_target] hot=%lu wait=%lu\n", GetThreadId(th[0]), GetThreadId(th[1]));
    fflush(stdout);

    // honest alertable wait in the main thread too -- an extra hijack candidate
    for (int i = 0; i < 100000 && !g_stop; i++) {
        SleepEx(500, TRUE);
        if (i % 20 == 0) {
            printf("[sc_target] alive\n");
            fflush(stdout);
        }
    }
    g_stop = 1;
    WaitForMultipleObjects(2, th, TRUE, 2000);
    return 0;
}
