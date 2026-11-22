#include <windows.h>
#include <cstdio>
static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_DESTROY: PostQuitMessage(0); return 0;
    case WM_CLOSE: DestroyWindow(h); return 0;
    }
    return DefWindowProcW(h, m, w, l);
}
int main()
{
    WNDCLASSW wc = {}; wc.lpfnWndProc = WndProc; wc.hInstance = GetModuleHandleW(0);
    wc.lpszClassName = L"scWndTarget"; RegisterClassW(&wc);
    HWND h = CreateWindowExW(0, L"scWndTarget", L"sc wnd target", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                             100, 100, 800, 600, 0, 0, wc.hInstance, 0);
    printf("[wnd_target] pid=%lu hwnd=%p tid=%lu\n", GetCurrentProcessId(), (void*)h, GetCurrentThreadId());
    fflush(stdout);
    for (;;) {
        /* alertable wait: user apcs land here, and messages keep coming */
        LARGE_INTEGER qpc; QueryPerformanceCounter(&qpc);   /* per-frame timing call */
        DWORD r = MsgWaitForMultipleObjectsEx(0, nullptr, 100, QS_ALLINPUT, MWMO_ALERTABLE);
        if (r == WAIT_OBJECT_0) {
            MSG msg;
            while (PeekMessageW(&msg, 0, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) return 0;
                TranslateMessage(&msg); DispatchMessageW(&msg);
            }
        }
    }
}
