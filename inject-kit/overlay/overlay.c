// overlay.c -- external overlay: reads sc_feed.bin, projects world points, draws
// 渲染后端：DirectComposition + D3D11 + D2D（替代原来的 GDI + 颜色键透明）
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <math.h>

#include "dc_render.h"

#define FEED_PATH L"C:\\ProgramData\\sc_feed.bin"

#define FEED_MAX_ENT 24
typedef struct _EINFO {
    unsigned int  hp;
    unsigned int  hpMax;
    unsigned int  sh;
    unsigned int  shMax;
    unsigned char team;
    unsigned char life;
    unsigned char nameLen;
    unsigned char flags;
    char          name[20];
} EINFO;
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
    EINFO info[FEED_MAX_ENT];
} FEED;

static void DrawBars(CV* cv, int k, int x0, int y0, int bh, int wid);
static void SaveConfig(void);
static int PickTarget(int w, int h);
static void SkyNadeAssist(int w, int h);

static HWND  g_overlay, g_game;
static CV*   g_cv;
static FEED  g_feed;
static int   g_have;
static FEED  g_last;
static DWORD g_lastGood;
static double g_fps;
static double g_fov = 110.0;        /* ????????? FOV?? EffectiveFov ??? */
static double g_gameFov = 110.0;    /* ??? FOV ????4:3 ??? */
#define DPI 3.14159265358979

/* Apex ? FOV ??? 4:3 ????? FOV?
 * ?????? FOV = 2*atan( tan(gameFov/2) * (aspect)/(4/3) )
 * 16:9 + gameFov=110 ? 124.6??????????? */
static double EffectiveFov(int w, int h)
{
    double t = tan(g_gameFov * DPI / 360.0);
    double asp = (h > 0) ? ((double)w / (double)h) : (16.0 / 9.0);
    double v;
    t *= asp / (4.0 / 3.0);
    v = 2.0 * atan(t) * 180.0 / DPI;
    if (v < 20.0) v = 20.0;
    if (v > 175.0) v = 175.0;
    return v;
}
static double g_offX = 0.0, g_offY = 0.0;
static int    g_fovLocked = 0;
/* ---- SkyNade ???? ---- */
static int    g_nadeOn   = 0;
static double g_nadeV    = 1500.0;  /* in/s ???? */
static double g_nadeG    = 725.0;   /* in/s? ???? */
static double g_nadeFuse = 4.0;
static double g_vReq      = 0;
static int    g_nadeTarget = -1;
static int    g_latch      = -1;   /* ? Shift+?? ??????? */      /* ?????????????? */
/* ---- SkyNade ???? ---- */
static int    g_assistOn  = 1;      /* 1 = ?? Shift+?? ???? */
static double g_pxPerDeg  = 18.18;  /* ???? / ??????? 50px ? 2.75?? */
static double g_calPitch  = 0;      /* ??????? */
static int    g_calPx     = 0;      /* ????????? */
static int    g_calValid  = 0;
static double g_stuckPitch = 0;     /* ????????????? */
static int    g_stuckCnt   = 0;     /* ??????? */
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
    double f, fovh = EffectiveFov(w, h);

    if (z <= 1.0) return 0;
    f = (w / 2.0) / tan(fovh * 3.14159265358979 / 360.0);
    *sx = (float)(w / 2.0 + g_offX + f * x / z);
    *sy = (float)(h / 2.0 + g_offY - f * y / z);
    (void)ux; (void)uy; (void)uz;
    return 1;
}

static int g_hotkey = 0;
static int g_cfgDirty = 0;
static DWORD g_cfgSaveAt = 0;
static void PollKeys(void)
{
    static int last = 0;
    int now = (GetAsyncKeyState(VK_F1) & 0x8000) ? 1 : 0;
    if (now && !last) { g_gameFov -= 0.5; g_fovLocked = 1; g_cfgDirty = 1; }
    last = now;
    now = (GetAsyncKeyState(VK_F2) & 0x8000) ? 1 : 0;
    if (now && last != 2) { g_gameFov += 0.5; g_fovLocked = 1; g_cfgDirty = 1; }
    if (now) last = 2; else if (!now && last == 2) last = 0;
    if (GetAsyncKeyState(VK_F3) & 0x8000) { g_offY -= 1.0; g_fovLocked = 1; g_cfgDirty = 1; }
    if (GetAsyncKeyState(VK_F4) & 0x8000) { g_offY += 1.0; g_fovLocked = 1; g_cfgDirty = 1; }
    if (GetAsyncKeyState(VK_F5) & 0x8000) { g_offX -= 1.0; g_fovLocked = 1; g_cfgDirty = 1; }
    if (GetAsyncKeyState(VK_F6) & 0x8000) { g_offX += 1.0; g_fovLocked = 1; g_cfgDirty = 1; }
    {
        static int n7 = 0;
        int c7 = (GetAsyncKeyState(VK_F7) & 0x8000) ? 1 : 0;
        if (c7 && !n7) g_nadeOn = !g_nadeOn;
        n7 = c7;
    }
    if (g_cfgDirty && GetTickCount() - g_cfgSaveAt > 800) { SaveConfig(); g_cfgDirty = 0; g_cfgSaveAt = GetTickCount(); }
    if (GetAsyncKeyState(VK_F8)  & 0x8000) { if (g_nadeV > 100) g_nadeV -= 10; }
    if (GetAsyncKeyState(VK_F9)  & 0x8000) { g_nadeV += 10; }
    if (GetAsyncKeyState(VK_F10) & 0x8000) { if (g_nadeG > 100) g_nadeG -= 10; }
    if (GetAsyncKeyState(VK_F11) & 0x8000) { g_nadeG += 10; }
}


/* ---- SkyNade ????? ----
 * ???? t??? v0 ?????????
 *   A = D / t                ????????
 *   B = (dh + 0.5*g*t^2) / t ????????
 *   reqV = sqrt(A^2 + B^2)   ???????
 *   base = atan2(B, A)
 *   phi  = acos(reqV / v0)
 *   pitchLow  = base - phi   ??????????
 *   pitchHigh = base + phi   ???????????SkyNade ???
 * ???: reqV > v0 ????
 */
typedef struct { int ok; int mode; double D; double dh; double reqV; double low; double high; double use; double miss; } NADE_SOL;

static NADE_SOL SolveNade(double bx, double by, double bz, const float* tp)
{
    NADE_SOL r;
    double dx = tp[0] - bx, dy = tp[1] - by;
    double D = sqrt(dx * dx + dy * dy);
    double dh = tp[2] - bz;
    double halfGt2 = 0.5 * g_nadeG * g_nadeFuse * g_nadeFuse;
    double A, B, reqV, base, cosPhi, phi;
    RtlZeroMemory(&r, sizeof(r));
    r.D = D; r.dh = dh;
    if (D < 1.0) return r;
    A = D / g_nadeFuse;
    B = (dh + halfGt2) / g_nadeFuse;
    reqV = sqrt(A * A + B * B);
    r.reqV = reqV;
    if (reqV > g_nadeV + 0.1) {
        /* ??????????????phi=0?? base ???
         * ????????????????????????? */
        r.low = r.high = atan2(B, A) * 180.0 / 3.14159265358979;
        r.mode = 3;
        r.use = r.low;
        r.miss = (reqV - g_nadeV) * g_nadeFuse * 0.01905;
        r.ok = 1;
        return r;
    }
    base = atan2(B, A);
    cosPhi = reqV / g_nadeV;
    if (cosPhi > 1.0) cosPhi = 1.0;
    if (cosPhi < -1.0) cosPhi = -1.0;
    phi = acos(cosPhi);
    r.low  = (base - phi) * 180.0 / 3.14159265358979;
    r.high = (base + phi) * 180.0 / 3.14159265358979;
    r.ok = 1;
    /* ???? ? ??????????????????????????
     * ? base ?????? = (reqV - v0) * t????????? */
    r.use  = base * 180.0 / 3.14159265358979;
    r.miss = (reqV - g_nadeV) * g_nadeFuse * 0.01905;   /* ???=????=??? */
    r.mode = (r.use <= 89.0) ? 2 : 0;
    return r;
}

static void DrawNadeTraj(CV* cv, int w, int h)
{
    const double PI = 3.14159265358979;
    double bx = g_feed.cam[0], by = g_feed.cam[1], bz = g_feed.cam[2];
    int k, best = -1;
    double bestScore = 1e18;
    NADE_SOL sol;
    char info[220];

    RtlZeroMemory(&sol, sizeof(sol));

    best = PickTarget(w, h);
    if (best < 0) return;
    g_nadeTarget = best;

    sol = SolveNade(bx, by, bz, g_feed.ent[best]);
    g_vReq = sol.reqV;

    /* ?????????? */
    if (sol.ok) {
        double yawT = atan2(g_feed.ent[best][1] - by, g_feed.ent[best][0] - bx);
        double p = -sol.use * PI / 180.0;       /* Apex: ???? */
        double vx = cos(p) * cos(yawT) * g_nadeV;
        double vy = cos(p) * sin(yawT) * g_nadeV;
        double vz = -sin(p) * g_nadeV;
        double t, dt = 0.02;
        float lastx = 0, lasty = 0;
        int have = 0;
        for (t = 0; t <= g_nadeFuse + 1e-9; t += dt) {
            float pt[3], sx, sy;
            pt[0] = (float)(bx + vx * t);
            pt[1] = (float)(by + vy * t);
            pt[2] = (float)(bz + vz * t - 0.5 * g_nadeG * t * t);
            if (WorldToScreen(pt, w, h, &sx, &sy)) {
                if (have) CV_Line(cv, lastx, lasty, sx, sy, 1.0f, 0.82f, 0.24f, 2.0f);
                lastx = sx; lasty = sy; have = 1;
            } else have = 0;
        }
    }

    /* 目标点 + 准星 */
    {
        float sx, sy;
        if (WorldToScreen(g_feed.ent[best], w, h, &sx, &sy)) {
            CV_Circle(cv, sx, sy, 10.0f, 1.0f, 0.27f, 0.27f, 2.0f);
            CV_Line(cv, sx - 16, sy, sx + 16, sy, 1.0f, 0.27f, 0.27f, 2.0f);
            CV_Line(cv, sx, sy - 16, sx, sy + 16, 1.0f, 0.27f, 0.27f, 2.0f);

            if (sol.ok) {
                double now = g_feed.ang[0];
                double need = -sol.use;                  /* ????? pitch */
                const char* hint = (now < need - 3) ? " down" : ((now > need + 3) ? " up" : " OK");
                _snprintf_s(info, sizeof(info), _TRUNCATE,
                            "SkyNade D=%.0fm Vreq=%.0f Vnow=%.0f need=%.1f now=%.1f%s miss=%+.1fm(+?/-?)",
                            sol.D * 0.01905, sol.reqV, g_nadeV,
                            need, now, hint, sol.miss);
                if (sol.mode == 3)
                    CV_Text(cv, sx + 20, sy - 8, info, (int)strlen(info), 1.0f, 0.47f, 0.24f);
                else if (fabs(now - need) < 3)
                    CV_Text(cv, sx + 20, sy - 8, info, (int)strlen(info), 0.31f, 1.0f, 0.31f);
                else
                    CV_Text(cv, sx + 20, sy - 8, info, (int)strlen(info), 1.0f, 0.82f, 0.24f);
            } else {
                _snprintf_s(info, sizeof(info), _TRUNCATE,
                            "SkyNade D=%.0fm  NO SOLUTION  Vreq=%.0f > Vnow=%.0f  (max %.0fm)",
                            sol.D * 0.01905, sol.reqV, g_nadeV,
                            sqrt(g_nadeV * g_nadeV - 0.25 * g_nadeG * g_nadeG * g_nadeFuse * g_nadeFuse) * g_nadeFuse * 0.01905);
                CV_Text(cv, sx + 20, sy - 8, info, (int)strlen(info), 1.0f, 0.31f, 0.31f);
            }
        }
    }
}

/* ???? k ?????? */
static int EntBox(int k, int w, int h, float* x0, float* y0, float* x1, float* y1)
{
    float feet[3], head[3], sfx, sfy, shx, shy, bh, bw;
    if (k < 0 || k >= (int)g_feed.count || k >= FEED_MAX_ENT) return 0;
    feet[0] = g_feed.ent[k][0];
    feet[1] = g_feed.ent[k][1];
    feet[2] = g_feed.ent[k][2];
    head[0] = feet[0]; head[1] = feet[1]; head[2] = feet[2] + (float)g_boxH;
    if (!WorldToScreen(feet, w, h, &sfx, &sfy)) return 0;
    if (!WorldToScreen(head, w, h, &shx, &shy)) return 0;
    bh = sfy - shy;
    if (bh < 4 || bh > 4000) return 0;
    bw = bh * (float)g_boxW;
    if (bw < 6) bw = 6;
    *x0 = sfx - bw * 0.5f; *x1 = sfx + bw * 0.5f;
    *y0 = shy;             *y1 = sfy;
    return 1;
}

/* ????????????
 * Apex ???????SetCursorPos ??? warp ??????????
 * ????? mouse_event ????????? */
static void RecenterCursor(void)
{
    POINT pt;
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    if (sw <= 0 || sh <= 0) return;
    if (!GetCursorPos(&pt)) return;
    if (pt.x < 40 || pt.x > sw - 40 || pt.y < 40 || pt.y > sh - 40)
        SetCursorPos(sw / 2, sh / 2);
    else if (0) SetCursorPos(pt.x, pt.y);
}

/* ???????????????????????260px ??????????? */
static int PickTarget(int w, int h)
{
    int k, best = -1;
    double cx = w * 0.5, cy = h * 0.5;
    double bestDist = 1e18;
    for (k = 0; k < (int)g_feed.count && k < FEED_MAX_ENT; k++) {
        float x0, y0, x1, y1;
        double bx, by, d;
        if (!EntBox(k, w, h, &x0, &y0, &x1, &y1)) continue;
        if (cx >= x0 && cx <= x1 && cy >= y0 && cy <= y1) return k;
        bx = (x0 + x1) * 0.5; by = (y0 + y1) * 0.5;
        d = sqrt((bx - cx) * (bx - cx) + (by - cy) * (by - cy));
        if (d < bestDist) { bestDist = d; best = k; }
    }
    if (best >= 0 && bestDist > 400.0) return -1;
    return best;
}

/* SkyNade ?????????? && Shift && ?? ? ??????? */
static void SkyNadeAssist(int w, int h)
{
    int k, best = -1;
    double cx = w * 0.5, cy = h * 0.5;
    double bx = g_feed.cam[0], by = g_feed.cam[1], bz = g_feed.cam[2];
    double targetPitch, diff, px;

    if (!g_assistOn) return;
    if (!(GetAsyncKeyState(VK_SHIFT) & 0x8000) || !(GetAsyncKeyState(VK_LBUTTON) & 0x8000)) {
        g_latch = -1;                        /* ????? */
        return;
    }
    if (g_latch < 0) g_latch = PickTarget(w, h);   /* ?????? */
    best = g_latch;
    if (best < 0 || best >= (int)g_feed.count) return;

    {
        NADE_SOL sol = SolveNade(bx, by, bz, g_feed.ent[best]);
        if (!sol.ok || sol.mode == 0) return;
        targetPitch = -sol.use;
    }

    diff = targetPitch - g_feed.ang[0];
    if (fabs(diff) < 0.4) return;

    if (g_calValid) {
        double dPitch = g_feed.ang[0] - g_calPitch;
        if (g_calPx != 0 && fabs(dPitch) > 0.05 && fabs(dPitch) < 60.0) {
            double inst = fabs((double)g_calPx) / fabs(dPitch);
            if (inst > 1.0 && inst < 500.0)
                g_pxPerDeg = g_pxPerDeg * 0.85 + inst * 0.15;
        }
    }
    g_calPitch = g_feed.ang[0];
    g_calValid = 1;

    px = diff * g_pxPerDeg;
    {
        /* ???????????????60px ? 3.3 ?/? */
        double lim = 60.0;
        if (px >  lim) px =  lim;
        if (px < -lim) px = -lim;
        if (fabs(px) < 1.0) px = (px > 0) ? 1.0 : -1.0;
    }
    g_calPx = (int)px;
    mouse_event(0x0001, 0, (int)px, 0, 0);
    RecenterCursor();
}

static void Draw(CV* cv, int w, int h)
{
    PollKeys();
    if (g_have && g_feed.ok) SkyNadeAssist(w, h);
    char buf[160];
    float sx, sy, sx2, sy2;
    float feet[3], head[3];

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "sc overlay %dx%d fps=%.0f feed=%s fov=%.1f offX=%.0f offY=%.0f  cam=(%.0f,%.0f,%.0f) ang=(%.1f,%.1f)",
                w, h, g_fps, g_have ? "ok" : "none", g_fov, g_offX, g_offY,
                g_feed.cam[0], g_feed.cam[1], g_feed.cam[2], g_feed.ang[0], g_feed.ang[1]);
    CV_Text(cv, 8, 8, buf, (int)strlen(buf), 0.0f, 1.0f, 0.0f);

    if (g_lastGood && (GetTickCount() - g_lastGood) < 1500) {
        /* ---- self box: independent, never blocks the entity loop ---- */
        feet[0] = g_feed.pos[0]; feet[1] = g_feed.pos[1]; feet[2] = g_feed.pos[2];
        head[0] = feet[0]; head[1] = feet[1]; head[2] = feet[2] + 72.0f;
        if (WorldToScreen(feet, w, h, &sx, &sy) && WorldToScreen(head, w, h, &sx2, &sy2)) {
            float bh = sy - sy2;
            float bw = bh * (float)g_boxW;
            if (bh > 4 && bh < 4000)
                CV_Rect(cv, sx - bw / 2, sy2, sx + bw / 2, sy, 0.0f, 1.0f, 0.0f, 2.0f);
        }

        /* ---- other entities: always drawn regardless of self projection ---- */
        {
            unsigned k;
            for (k = 0; k < g_feed.count && k < FEED_MAX_ENT; k++) {
                float e[3], s1 = 0, s2 = 0, s3 = 0, s4 = 0;
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
                        double meters = sqrt(dx*dx + dy*dy + dz*dz) * 0.01905;
                        if (wid < 6) wid = 6;
                        CV_Rect(cv, s1 - wid / 2, s4, s1 + wid / 2, s2, 1.0f, 0.31f, 0.31f, 2.0f);
                        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%.0fm", meters);
                        CV_Text(cv, s1 - wid / 2, s4 - 15, buf, (int)strlen(buf), 1.0f, 0.31f, 0.31f);
                        DrawBars(cv, (int)k, (int)(s1 - wid / 2), (int)s4, (int)hgt, (int)wid);
                    }
                }
            }
        }
    }

    if (g_nadeOn) DrawNadeTraj(cv, w, h);
}


/* HP / 护甲 / 名字 */
static void DrawBars(CV* cv, int k, int x0, int y0, int bh, int wid)
{
    const EINFO* inf;
    int bx;
    if (k < 0 || k >= FEED_MAX_ENT) return;
    inf = &g_feed.info[k];
    if (!inf->flags || bh < 8) return;
    bx = x0 - 7;

    if (inf->hpMax > 0 && inf->hpMax < 10000) {
        double f = (double)inf->hp / (double)inf->hpMax;
        if (f > 1.0) f = 1.0; if (f < 0.0) f = 0.0;
        CV_FillRect(cv, (float)bx, (float)y0, (float)(bx + 4), (float)(y0 + bh),
                    0.10f, 0.10f, 0.10f);
        CV_FillRect(cv, (float)bx, (float)(y0 + (int)(bh * (1.0 - f))), (float)(bx + 4),
                    (float)(y0 + bh), 0.27f, 0.82f, 0.27f);
    }
    if (inf->shMax > 0 && inf->shMax < 10000) {
        double f = (double)inf->sh / (double)inf->shMax;
        if (f > 1.0) f = 1.0; if (f < 0.0) f = 0.0;
        CV_FillRect(cv, (float)(bx + 5), (float)y0, (float)(bx + 9), (float)(y0 + bh),
                    0.10f, 0.10f, 0.10f);
        CV_FillRect(cv, (float)(bx + 5), (float)(y0 + (int)(bh * (1.0 - f))), (float)(bx + 9),
                    (float)(y0 + bh), 0.31f, 0.63f, 1.0f);
    }
    if (inf->nameLen > 0 && inf->nameLen < 20)
        CV_Text(cv, (float)x0, (float)(y0 - 30), inf->name, inf->nameLen, 0.90f, 0.90f, 0.90f);
    (void)wid;
}

static void LoadConfig(void)
{
    char buf[512];
    FILE* f = NULL;
    if (fopen_s(&f, "C:\\ProgramData\\sc_overlay.ini", "r") != 0 || !f) return;
    while (fgets(buf, sizeof(buf), f)) {
        double v;
        if (sscanf_s(buf, "gameFov=%lf", &v) == 1 && v > 20 && v < 170 && !g_fovLocked) g_gameFov = v;
        else if (sscanf_s(buf, "fov=%lf", &v) == 1 && v > 20 && v < 180) g_fov = v;
        else if (sscanf_s(buf, "boxH=%lf", &v) == 1 && v > 10 && v < 200) g_boxH = v;
        else if (sscanf_s(buf, "boxW=%lf", &v) == 1 && v > 0.1 && v < 2.0) g_boxW = v;
        else if (sscanf_s(buf, "offX=%lf", &v) == 1 && v > -2000 && v < 2000) g_offX = v;
        else if (sscanf_s(buf, "offY=%lf", &v) == 1 && v > -2000 && v < 2000) g_offY = v;
        else if (sscanf_s(buf, "pxPerDeg=%lf", &v) == 1 && v > 1 && v < 500) g_pxPerDeg = v;
        else if (sscanf_s(buf, "assist=%lf", &v) == 1) g_assistOn = (v != 0);
    }
    fclose(f);
}

static void SaveConfig(void)
{
    FILE* f = NULL;
    if (fopen_s(&f, "C:\\ProgramData\\sc_overlay.ini", "w") != 0 || !f) return;
    fprintf(f, "gameFov=%.2f\n", g_gameFov);
    fprintf(f, "fov=%.2f\n", g_fov);
    fprintf(f, "offX=%.2f\n", g_offX);
    fprintf(f, "offY=%.2f\n", g_offY);
    fprintf(f, "boxH=%.2f\n", g_boxH);
    fprintf(f, "boxW=%.3f\n", g_boxW);
    fprintf(f, "pxPerDeg=%.3f\n", g_pxPerDeg);
    fprintf(f, "assist=%d\n", g_assistOn);
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
        /* DComp 自绘，无需 GDI 重绘；仅验证区域 */
        PAINTSTRUCT ps;
        BeginPaint(hwnd, &ps);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_NCHITTEST:
        return HTTRANSPARENT;              /* 鼠标穿透（配合 WS_EX_TRANSPARENT） */
    case WM_TIMER: {
        RECT gr, rc;
        DWORD now = GetTickCount();
        int w, h;
        static RECT lastGr;
        if (!IsWindow(g_game)) g_game = FindGameWindow();
        if (g_game && GetWindowRect(g_game, &gr)) {
            /* 只有矩形真的变了才动窗口：SetWindowPos 每帧调用会显著掉帧 */
            if (gr.left != lastGr.left || gr.top != lastGr.top ||
                gr.right != lastGr.right || gr.bottom != lastGr.bottom) {
                lastGr = gr;
                SetWindowPos(hwnd, HWND_TOPMOST, gr.left, gr.top,
                             gr.right - gr.left, gr.bottom - gr.top,
                             SWP_NOACTIVATE | SWP_SHOWWINDOW);
            }
        }
        Reload();
        frames++;
        if (now - last >= 1000) { g_fps = frames; frames = 0; last = now; LoadConfig(); }

        GetClientRect(hwnd, &rc);
        w = rc.right - rc.left;
        h = rc.bottom - rc.top;
        if (g_cv && w > 0 && h > 0 && CV_Begin(g_cv)) {
            Draw(g_cv, w, h);
            CV_End(g_cv);
        }
        return 0;
    }
    case WM_SIZE:
        /* 尺寸变化由 CV_Begin 内部按需重建 swapchain */
        return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, PWSTR cmd, int show)
{
    {   HMODULE u32 = GetModuleHandleA("user32.dll");
        if (u32) { typedef BOOL (WINAPI *P)(void); P p2 = (P)GetProcAddress(u32, "SetProcessDPIAware"); if (p2) p2(); }
    }
    WNDCLASSW wc = {0};
    MSG msg;
    (void)prev; (void)cmd; (void)show;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.lpszClassName = L"scOverlay";
    RegisterClassW(&wc);
    LoadConfig();
    g_overlay = CreateWindowExW(
        WS_EX_NOREDIRECTIONBITMAP | WS_EX_TRANSPARENT | WS_EX_TOPMOST
        | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
        L"scOverlay", L"sc overlay", WS_POPUP, 0, 0, 800, 600, NULL, NULL, inst, NULL);
    if (!g_overlay) return 1;
    /* DirectComposition 后端：不再需要 SetLayeredWindowAttributes 颜色键 */
    g_cv = CV_Create(g_overlay);
    if (!g_cv) return 2;
    {   const char* e = CV_Error(g_cv);
        if (e) {
            MessageBoxA(NULL, e, "DirectComposition 初始化失败", MB_ICONERROR);
            CV_Destroy(g_cv);
            return 3;
        }
    }
    ShowWindow(g_overlay, SW_SHOWNOACTIVATE);
    /* 定时器默认精度 ~15.6ms，会吃掉一半帧率 */
    { typedef UINT (WINAPI *PTBP)(UINT); HMODULE w = GetModuleHandleA("winmm.dll");
      if (w) { PTBP f2 = (PTBP)GetProcAddress(w, "timeBeginPeriod"); if (f2) f2(1); } }
    SetTimer(g_overlay, 1, 15, NULL);
    while (GetMessageW(&msg, NULL, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    if (g_cv) CV_Destroy(g_cv);
    return 0;
}
