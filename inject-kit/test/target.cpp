// target.exe —— 本地测试靶（模拟"受保护目标"）
// 打印 PID/TID，循环时不断回到用户态，方便验证 APC 注入。
#include <windows.h>
#include <cstdio>

static volatile LONG g_ticks = 0;

int main()
{
    printf("[target] pid=%lu tid=%lu\n", GetCurrentProcessId(), GetCurrentThreadId());
    printf("[target] waiting for injection... (ctrl+c to exit)\n");
    fflush(stdout);

    for (;;)
    {
        // 可告警等待：用户态 APC 只会在这里被投递（Sleep 不可告警）
        SleepEx(500, TRUE);
        g_ticks++;
        if (g_ticks % 10 == 0)
        {
            printf("[target] alive ticks=%ld\n", (long)g_ticks);
            fflush(stdout);
        }
    }
    return 0;
}
