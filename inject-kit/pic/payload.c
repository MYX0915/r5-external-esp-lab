// payload.c -- position independent payload, called as a user APC normal routine.
//   no imports, no strings, no globals: everything comes from the table the
//   kernel driver fills in inside the same zero page.
//
//   rcx = table pointer (NormalContext)
//   table layout (must match TABLE_OFF_* in sc3.c):
//     0x00 counter      0x08 magic        0x10 pid
//     0x18 CreateFileA  0x20 WriteFile    0x28 CloseHandle  0x30 GetCurrentProcessId
//     0x38 path (ANSI)
typedef unsigned __int64 U64;
typedef unsigned int U32;
typedef void* HANDLE;

typedef struct _TABLE {
    U64 counter;
    U64 magic;
    U64 pid;
    void* pfCreateFileA;
    void* pfWriteFile;
    void* pfCloseHandle;
    void* pfGetCurrentProcessId;
    char  path[260];
} TABLE;

typedef HANDLE(__stdcall* CF)(const char*, U32, U32, void*, U32, U32, void*);
typedef int(__stdcall* WF)(HANDLE, const void*, U32, U32*, void*);
typedef int(__stdcall* CH)(HANDLE);
typedef U32(__stdcall* GP)(void);

__declspec(noinline) void __fastcall Payload(TABLE* t)
{
    HANDLE h;

    t->counter++;
    t->magic = 0x5C0DE5C0ull;

    if (t->pfGetCurrentProcessId) t->pid = ((GP)t->pfGetCurrentProcessId)();

    if (!t->pfCreateFileA || !t->pfWriteFile || !t->pfCloseHandle) return;

    h = ((CF)t->pfCreateFileA)(t->path, 0x40000000u, 1u, 0, 2u, 0x80u, 0);
    if (h == (HANDLE)(U64)-1) return;

    {
        U64 rec[2];
        U32 written = 0;
        rec[0] = t->pid;
        rec[1] = 0x4B4F434950ull;          /* "PICOK" */
        ((WF)t->pfWriteFile)(h, rec, sizeof(rec), &written, 0);
    }
    ((CH)t->pfCloseHandle)(h);
}
