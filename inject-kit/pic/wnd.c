// wnd.c -- position independent window-proc payload.
//
//   Installer(TABLE*)      : called through a user APC, finds our top-level window
//                            by pid (largest visible one) and swaps its WndProc.
//   OurWndProc(TABLE*, ...): the replacement proc. First message: restore the old
//                            proc, do the work, then forward through CallWindowProcW.
//
// The replacement entry point is a stub the driver emits (it bakes the table
// address and this function's address as immediates), because C cannot capture
// its own RIP without a relocation.
typedef unsigned __int64 U64;
typedef unsigned int U32;
typedef void* HANDLE;
typedef void* HWND;

typedef struct { long left, top, right, bottom; } RECT;

typedef struct _TABLE {
    U64 counter;                        /* 0x00 */
    U64 magic;                          /* 0x08 */
    U64 pid;                            /* 0x10 */
    void* pfCreateFileA;                /* 0x18 */
    void* pfWriteFile;                  /* 0x20 */
    void* pfCloseHandle;                /* 0x28 */
    void* pfGetCurrentProcessId;        /* 0x30 */
    void* pfEnumWindows;                /* 0x38 */
    void* pfGetWindowThreadProcessId;   /* 0x40 */
    void* pfIsWindowVisible;            /* 0x48 */
    void* pfGetWindowRect;              /* 0x50 */
    void* pfSetWindowLongPtrW;          /* 0x58 */
    void* pfGetWindowLongPtrW;          /* 0x60 */
    void* pfCallWindowProcW;            /* 0x68 */
    U64   wndProcVa;                    /* 0x70  stub the driver wrote */
    U64   tid;                          /* 0x78  ui thread of the window */
    U64   hwnd;                         /* 0x80 */
    U64   oldProc;                      /* 0x88 */
    U64   bestArea;                     /* 0x90 */
    U64   hit;                          /* 0x98 */
    char  path[260];                    /* 0xA0 */
    U64   beacon;                       /* 0x1A8 */
    void* pfFindWindowW;                /* 0x1B0 */
    void* pfGetLastError;               /* 0x1B8 */
    unsigned short cls[64];             /* 0x1C0 */
} TABLE;

typedef HANDLE(__stdcall* CF)(const char*, U32, U32, void*, U32, U32, void*);
typedef int(__stdcall* WF)(HANDLE, const void*, U32, U32*, void*);
typedef int(__stdcall* CH)(HANDLE);
typedef U32(__stdcall* GP)(void);
typedef int(__stdcall* EW)(void* cb, long long param);
typedef U32(__stdcall* GWTP)(HWND, U32*);
typedef int(__stdcall* IWV)(HWND);
typedef int(__stdcall* GWR)(HWND, RECT*);
typedef long long(__stdcall* SWLP)(HWND, int, long long);
typedef long long(__stdcall* CWPW)(void*, HWND, U32, U64, U64);
typedef HWND(__stdcall* FWW)(const unsigned short*, const unsigned short*);
typedef U32(__stdcall* GLE)(void);

__declspec(dllexport, noinline) U64 OurWndProc(TABLE* t, HWND h, U32 msg, U64 wp, U64 lp);

static void WriteMark(TABLE* t)
{
    HANDLE h;
    U64 rec[2];
    U32 written = 0;

    if (!t->pfCreateFileA || !t->pfWriteFile || !t->pfCloseHandle) return;
    h = ((CF)t->pfCreateFileA)(t->path, 0x40000000u, 1u, 0, 2u, 0x80u, 0);
    if (h == (HANDLE)(U64)-1) return;
    rec[0] = t->pid;
    rec[1] = 0x4B4F434950ull;            /* "PICOK" */
    ((WF)t->pfWriteFile)(h, rec, sizeof(rec), &written, 0);
    ((CH)t->pfCloseHandle)(h);
}

static int __stdcall EnumCb(HWND h, long long param)
{
    TABLE* t = (TABLE*)param;
    U32 pid = 0;
    RECT r;
    long area;

    if (!t->pfGetWindowThreadProcessId || !t->pfIsWindowVisible || !t->pfGetWindowRect) return 1;
    {
        U32 tid = (U32)((GWTP)t->pfGetWindowThreadProcessId)(h, &pid);
        if ((U64)pid != t->pid || !((IWV)t->pfIsWindowVisible)(h)) return 1;
        if (tid) t->tid = (U64)tid;
    }
    if ((U64)pid != t->pid) return 1;
    if (!((IWV)t->pfIsWindowVisible)(h)) return 1;
    r.left = r.top = r.right = r.bottom = 0;
    if (!((GWR)t->pfGetWindowRect)(h, &r)) return 1;
    area = (r.right - r.left) * (r.bottom - r.top);
    if (area > (long)t->bestArea) {
        t->bestArea = (U64)area;
        t->hwnd = (U64)h;
    }
    return 1;
}

/* entry: rcx = table (driver passes it as NormalContext) */
__declspec(dllexport, noinline) void Installer(TABLE* t)
{
    U64 old;

    t->counter++;
    t->magic = 0x5C0DE5C0ull;
    if (t->pfGetCurrentProcessId) t->pid = ((GP)t->pfGetCurrentProcessId)();

    t->hwnd = 0;
    t->bestArea = 0;
    if (t->pfFindWindowW && t->cls[0]) {
        HWND h = ((FWW)t->pfFindWindowW)(t->cls, 0);
        if (h) {
            U32 pid = 0;
            U32 tid = (U32)((GWTP)t->pfGetWindowThreadProcessId)(h, &pid);
            if ((U64)pid == t->pid && ((IWV)t->pfIsWindowVisible)(h)) {
                t->hwnd = (U64)h;
                t->tid = (U64)tid;
            }
        }
        return;                       /* class given: never fall back to enum */
    }
    if (!t->pfEnumWindows) return;
    ((EW)t->pfEnumWindows)((void*)EnumCb, (long long)t);

    (void)old;
}

/* must run on the thread that owns the window: SetWindowLongPtrW(GWLP_WNDPROC)
   is not allowed across threads (it just returns 0) */
__declspec(dllexport, noinline) void SwapProc(TABLE* t)
{
    if (!t) return;
    t->beacon = 0x51570000ull | 1;                      /* entered */
    if (!t->hwnd || !t->wndProcVa || !t->pfSetWindowLongPtrW) return;
    if (t->oldProc) return;
    t->oldProc = ((SWLP)t->pfSetWindowLongPtrW)((HWND)t->hwnd, -4 /* GWLP_WNDPROC */,
                                                (long long)t->wndProcVa);
    {
        U32 err = 0;
        if (!t->oldProc && t->pfGetLastError) err = ((GLE)t->pfGetLastError)();
        t->beacon = ((U64)err << 32) | 0x5157ull;
    }
}

/* called by the driver stub as OurWndProc(table, hwnd, msg, wp, lp) */
__declspec(dllexport, noinline) U64 OurWndProc(TABLE* t, HWND h, U32 msg, U64 wp, U64 lp)
{
    if (t && t->magic == 0x5C0DE5C0ull && t->oldProc && !t->hit) {
        t->hit = 1;
        /* restore first: WriteFile can pump messages and re-enter this proc */
        ((SWLP)t->pfSetWindowLongPtrW)(h, -4, (long long)t->oldProc);
        WriteMark(t);
    }
    if (t && t->oldProc && t->pfCallWindowProcW)
        return ((CWPW)t->pfCallWindowProcW)((void*)t->oldProc, h, msg, wp, lp);
    return 0;
}
