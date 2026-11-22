// payload.dll —— 注入验证用载荷：DllMain 里落一个文件，证明代码真的在目标进程里跑了
#include <windows.h>
#include <cstdio>

static void WriteProof(const char* tag)
{
    wchar_t path[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, path);
    if (!n) return;
    wcscat_s(path, L"kmap-injected.txt");

    FILE* f = nullptr;
    if (_wfopen_s(&f, path, L"a") == 0 && f)
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "%s pid=%lu tid=%lu module=%p time=%04d-%02d-%02d %02d:%02d:%02d\n",
                tag, GetCurrentProcessId(), GetCurrentThreadId(),
                (void*)GetModuleHandleW(nullptr),
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        fclose(f);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        WriteProof("DLL_PROCESS_ATTACH ok");
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        WriteProof("DLL_PROCESS_DETACH");
    }
    return TRUE;
}
