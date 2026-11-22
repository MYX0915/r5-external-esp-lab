// overlay.c -- external overlay: reads sc_feed.bin, projects world points, draws
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <math.h>

#define KEYCOLOR RGB(255, 0, 255)
#define FEED_PATH L"C:\\ProgramData\\sc_feed.bin"

#define FEED_MAX_ENT 24
typedef struct _FEED {
    unsigned int  magic;
    unsigned int  version;
    float cam[3];
    float ang[3];      /* pitch, yaw, roll (degrees) */
    float pos[3];      /* local entity origin */
    unsigned int  count;   /* other players of the same class */
    unsigned int  ok;
    unsigned long long inst;
    float ent[FEED_MAX_ENT][3];
} FEED;

static HWND  g_overlay, g_game;
static FEED  g_feed;
static int   g_have;
static FEED  g_last;
static DWORD g_lastGood;
static double g_fps;
static double g_fov = 90.0;
static double g_boxH = 72.0;
static double g_boxW = 0.42;

static HWND FindGameWindow(void)
{
    HWND h = FindWindowW(L"Respawn001", NULL);
    if (!h) h = FindWindowW(NULL, L"Apex Legends");
    return h;
}

/* world -> screen; returns 0 when behind the camera */
/* ---- per-entity motion tracking: extrapolate between low-rate updates ---- */
#define TRK_MAX 64
static struct {
    float pos[3];
    float vel[3];
    unsigned long long t;      /* GetTickCount64 when pos was captured */
    int   used;
} g_trk[TRK_MAX];
static float g_smooth[TRK_MAX][3];

static void TrackUpdate(int slot, const float* p)
{
    unsigned long long now = GetTickCount64();
    int i, best = -1;
    double bestd = 1e18;
    if (slot < 0 || slot >= TRK_MAX) return;
    /* find by proximity to keep identity stable across list reordering */
    for (i = 0; i < TRK_MAX; i++) {
        if (!g_trk[i].used) continue;
        {   double dx = g_trk[i].pos[0]-p[0], dy = g_trk[i].pos[1]-p[1], dz = g_trk[i].pos[2]-p[2];
            double d2 = dx*dx+dy*dy+dz*dz;
            if (d2 < bestd) { bestd = d2; best = i; }
        }
    }
    if (best >= 0 && bestd < 2500.0) {          /* same entity: update velocity */
        double dt = (now - g_trk[best].t) / 1000.0;
        if (dt > 0.02 && dt < 2.0) {
            double k = 1.0;
            for (i = 0; i < 3; i++)
                g_trk[best].vel[i] = (float)(g_trk[best].vel[i]*(1.0-k) + k*((p[i]-g_trk[best].pos[i])/dt));
        }
        for (i = 0; i < 3; i++) g_trk[best].pos[i] = p[i];
        g_trk[best].t = now;
        return;
    }
    for (i = 0; i < TRK_MAX; i++) {
        if (!g_trk[i].used) {
            g_trk[i].used = 1;
            for (int k2 = 0; k2 < 3; k2++) { g_trk[i].pos[k2] = p[k2]; g_trk[i].vel[k2] = 0.0f; g_smooth[i][k2] = p[k2]; }
            g_trk[i].t = now;
            return;
        }
    }
}

static void TrackPredict(const float* p, float* out)
{
    unsigned long long now = GetTickCount64();
    int i, best = -1;
    double bestd = 1e18;
    out[0] = p[0]; out[1] = p[1]; out[2] = p[2];
    for (i = 0; i < TRK_MAX; i++) {
        if (!g_trk[i].used) continue;
        {   double dx = g_trk[i].pos[0]-p[0], dy = g_trk[i].pos[1]-p[1], dz = g_trk[i].pos[2]-p[2];
            double d2 = dx*dx+dy*dy+dz*dz;
            if (d2 < bestd) { bestd = d2; best = i; }
        }
    }
    if (best >= 0 && bestd < 2500.0) {
        double dt = (now - g_trk[best].t) / 1000.0;
        if (dt < 0.0) dt = 0.0;
        if (dt > 0.30) dt = 0.30;               /* cap extrapolation */
        for (i = 0; i < 3; i++) out[i] = (float)(g_trk[best].pos[i] + g_trk[best].vel[i]*dt);
        /* glide: keep a smoothed copy that eases toward the predicted point */
        for (i = 0; i < 3; i++)
            g_smooth[best][i] += (float)((out[i] - g_smooth[best][i]) * 0.45);
        for (i = 0; i < 3; i++) out[i] = g_smooth[best][i];
    }
}

static int WorldToScreen(const float* p, int w, int h, float* sx, float* sy)
{
    double pitch = g_feed.ang[0] * 3.14159265358979 / 180.0;
    double yaw   = g_feed.ang[1] * 3.14159265358979 / 180.0;
    double dx = p[0] - g_feed.cam[0];
    double dy = p[1] - g_feed.cam[1];
    double dz = p[2] - g_feed.cam[2];
    double fx = cos(pitch) * cos(yaw), fy = cos(pitch) * sin(yaw), fz = -sin(pitch);
    double rx = sin(yaw),  ry = -cos(yaw), rz = 0.0;
    double ux = ry * fz - rz * fy, uy = rz * fx - rx * fz, uz = rx * fy - ry * fx;
    double z = dx * fx + dy * fy + dz * fz;
    double x = dx * rx + dy * ry + dz * rz;
    double y = dx * ux + dy * uy + dz * uz;
    double f, fovh = g_fov;

    if (z <= 1.0) return 0;
    f = (w / 2.0) / tan(fovh * 3.14159265358979 / 360.0);
    *sx = (float)(w / 2.0 + f * x / z);
    *sy = (float)(h / 2.0 - f * y / z);
    (void)ux; (void)uy; (void)uz;
    return 1;
}

static void Draw(HDC dc, int w, int h)
{
    HPEN pen = CreatePen(PS_SOLID, 2, RGB(0, 255, 0));
    char buf[160];
    float sx, sy, sx2, sy2;
    float feet[3], head[3];

    SetBkMode(dc, TRANSPARENT);
    SelectObject(dc, pen);
    SelectObject(dc, GetStockObject(NULL_BRUSH));   /* outline only, no fill */
    SetTextColor(dc, RGB(0, 255, 0));

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "sc overlay %dx%d fps=%.0f feed=%s  cam=(%.0f,%.0f,%.0f) ang=(%.1f,%.1f)",
                w, h, g_fps, g_have ? "ok" : "none",
                g_feed.cam[0], g_feed.cam[1], g_feed.cam[2], g_feed.ang[0], g_feed.ang[1]);
    TextOutA(dc, 8, 8, buf, (int)strlen(buf));

    if (g_lastGood && (GetTickCount() - g_lastGood) < 1500) {
        feet[0] = g_feed.pos[0]; feet[1] = g_feed.pos[1]; feet[2] = g_feed.pos[2];
        head[0] = feet[0]; head[1] = feet[1]; head[2] = feet[2] + 72.0f;
        if (WorldToScreen(feet, w, h, &sx, &sy) && WorldToScreen(head, w, h, &sx2, &sy2)) {
            float bh = sy - sy2;
            float bw = bh * (float)g_boxW;
            if (bh > 4 && bh < 4000) {
                Rectangle(dc, (int)(sx - bw / 2), (int)sy2, (int)(sx + bw / 2), (int)sy);
            } else {
                _snprintf_s(buf, sizeof(buf), _TRUNCATE, "proj off-screen h=%.0f", bh);
                TextOutA(dc, 8, 28, buf, (int)strlen(buf));
            }
            {   /* other players */
                HPEN ep = CreatePen(PS_SOLID, 2, RGB(255, 80, 80));
                unsigned k;
                SelectObject(dc, ep);
                for (k = 0; k < g_feed.count && k < FEED_MAX_ENT; k++) {
                    float e[3], s1, s2, s3, s4;
                    float top[3];
                    TrackUpdate((int)k, g_feed.ent[k]);
                    TrackPredict(g_feed.ent[k], e);
                    top[0] = e[0]; top[1] = e[1]; top[2] = e[2] + (float)g_boxH;
                    if (WorldToScreen(e, w, h, &s1, &s2) && WorldToScreen(top, w, h, &s3, &s4)) {
                        float hgt = s2 - s4;
                        float wid = hgt * (float)g_boxW;
                        if (hgt > 3 && hgt < 4000) {
                            double dx = e[0] - g_feed.pos[0];
                            double dy = e[1] - g_feed.pos[1];
                            double dz = e[2] - g_feed.pos[2];
                            double meters = sqrt(dx*dx + dy*dy + dz*dz) * 0.01905;  /* Apex unit -> m */
                            Rectangle(dc, (int)(s1 - wid / 2), (int)s4, (int)(s1 + wid / 2), (int)s2);
                            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%.0fm", meters);
                            TextOutA(dc, (int)(s1 - wid / 2), (int)s4 - 15, buf, (int)strlen(buf));
                        }
                    }
                }
                DeleteObject(ep);
            }
        } else {
            TextOutA(dc, 8, 28, "behind camera", 13);
        }
    }
    DeleteObject(pen);
}

static void LoadConfig(void)
{
    char buf[512];
    FILE* f = NULL;
    if (fopen_s(&f, "C:\\ProgramData\\sc_overlay.ini", "r") != 0 || !f) return;
    while (fgets(buf, sizeof(buf), f)) {
        double v;
        if (sscanf_s(buf, "fov=%lf", &v) == 1 && v > 20 && v < 170) g_fov = v;
        else if (sscanf_s(buf, "boxH=%lf", &v) == 1 && v > 10 && v < 200) g_boxH = v;
        else if (sscanf_s(buf, "boxW=%lf", &v) == 1 && v > 0.1 && v < 2.0) g_boxW = v;
    }
    fclose(f);
}

static void Reload(void)
{
    HANDLE hf = CreateFileW(FEED_PATH, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD got = 0;
    if (hf == INVALID_HANDLE_VALUE) { g_have = 0; return; }
    if (ReadFile(hf, &g_feed, sizeof(g_feed), &got, NULL) && got == sizeof(g_feed) && g_feed.magic == 0x44454546) {
        if (g_feed.ok && g_feed.inst) { g_last = g_feed; g_lastGood = GetTickCount(); }
        else if (g_lastGood && GetTickCount() - g_lastGood < 2000) g_feed = g_last;   /* hold last good frame */
        g_have = 1;
    } else {
        g_have = 0;
    }
    CloseHandle(hf);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    static DWORD last, frames;
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps; RECT rc; HBRUSH key;
        HDC dc = BeginPaint(hwnd, &ps);
        HDC mem; HBITMAP bmp, oldBmp;
        GetClientRect(hwnd, &rc);
        mem = CreateCompatibleDC(dc);                       /* double buffer: no flicker */
        bmp = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
        oldBmp = (HBITMAP)SelectObject(mem, bmp);
        key = CreateSolidBrush(KEYCOLOR);
        FillRect(mem, &rc, key);
        DeleteObject(key);
        Draw(mem, rc.right, rc.bottom);
        BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
        SelectObject(mem, oldBmp);
        DeleteObject(bmp);
        DeleteDC(mem);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_TIMER: {
        RECT gr;
        DWORD now = GetTickCount();
        if (!IsWindow(g_game)) g_game = FindGameWindow();
        if (g_game && GetWindowRect(g_game, &gr))
            SetWindowPos(hwnd, HWND_TOPMOST, gr.left, gr.top, gr.right - gr.left, gr.bottom - gr.top,
                         SWP_NOACTIVATE | SWP_SHOWWINDOW);
        Reload();
        frames++;
        if (now - last >= 1000) { g_fps = frames; frames = 0; last = now; LoadConfig(); }
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, PWSTR cmd, int show)
{
    WNDCLASSW wc = {0};
    MSG msg;
    (void)prev; (void)cmd; (void)show;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.lpszClassName = L"scOverlay";
    RegisterClassW(&wc);
    LoadConfig();
    g_overlay = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
        L"scOverlay", L"sc overlay", WS_POPUP, 0, 0, 800, 600, NULL, NULL, inst, NULL);
    if (!g_overlay) return 1;
    SetLayeredWindowAttributes(g_overlay, KEYCOLOR, 0, LWA_COLORKEY);
    ShowWindow(g_overlay, SW_SHOWNOACTIVATE);
    SetTimer(g_overlay, 1, 16, NULL);
    while (GetMessageW(&msg, NULL, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return 0;
}
