// sc3.sys -- Apex/Javelin probe: code execution without new thread / new executable page
//
// Staged (job file phase):
//   phase 1 : scan hot RW private regions -> stable 4KB page in hot region, or stable 512B
//             run inside a hot page -> canary survival check
//   phase 2 : phase1 + thread context probe (suspend / get RIP / resume, RIP unchanged)
//   phase 3 : phase2 + write shellcode + clear PTE bit63 (NX) + hijack existing thread
//             + counter verification + restore
//
// job file C:\ProgramData\sc_job.txt, key=value per line:
//   pid=13004          target pid (0 / missing -> poll by name)
//   name=r5apex_dx12.exe
//   phase=1
//   samples=5          sample count
//   gap=150            sample gap in ms
//   limit=800          max committed regions to enumerate
//   flush=ipi          tlb flush: ipi | local
//   slot=0x...         optional pinned slot va
//
// log: C:\ProgramData\kmaplog.txt (append + flush per line)
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>

#define LOG_FILE L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define JOB_FILE L"\\??\\C:\\ProgramData\\sc_job.txt"
#define SETTLE_SEC 20

typedef unsigned __int64 U64;

NTSYSAPI NTSTATUS NTAPI ZwSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
NTSYSAPI NTSTATUS NTAPI ZwResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG Class, PVOID Buffer, ULONG Length, PULONG ReturnLength);
NTSYSAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS From, PVOID FromAddr, PEPROCESS To, PVOID ToAddr,
                                            SIZE_T Len, KPROCESSOR_MODE Mode, PSIZE_T Done);
NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
NTSYSAPI NTSTATUS NTAPI PsGetContextThread(PETHREAD Thread, PCONTEXT Context, KPROCESSOR_MODE Mode);
NTSYSAPI NTSTATUS NTAPI PsSetContextThread(PETHREAD Thread, PCONTEXT Context, KPROCESSOR_MODE Mode);
NTSYSAPI BOOLEAN NTAPI MmIsAddressValid(PVOID VirtualAddress);
NTSYSAPI NTSTATUS NTAPI PsSetCreateProcessNotifyRoutine(PVOID Routine, BOOLEAN Remove);
NTSYSAPI PVOID NTAPI MmGetSystemRoutineAddress(PUNICODE_STRING Name);

/* APC primitives are exported but not in this WDK's km headers */
typedef struct _SC_KAPC {
    UCHAR Type;
    UCHAR SpareByte0;
    UCHAR Size;
    UCHAR SpareByte1;
    ULONG SpareLong0;
    PVOID Thread;
    LIST_ENTRY ApcListEntry;
    PVOID KernelRoutine;
    PVOID RundownRoutine;
    PVOID NormalRoutine;
    PVOID NormalContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    CCHAR ApcStateIndex;
    CCHAR ApcMode;
    BOOLEAN Inserted;
    UCHAR Pad0;
} SC_KAPC, *PSC_KAPC;

NTSYSAPI VOID NTAPI KeInitializeApc(PVOID Apc, PVOID Thread, ULONG Environment, PVOID KernelRoutine,
                                    PVOID RundownRoutine, PVOID NormalRoutine,
                                    KPROCESSOR_MODE ApcMode, PVOID NormalContext);
NTSYSAPI BOOLEAN NTAPI KeInsertQueueApc(PVOID Apc, PVOID SystemArgument1, PVOID SystemArgument2,
                                        LONG Increment);

typedef struct _SPI3 {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    /* followed by NumberOfThreads * STI3 */
} SPI3, *PSPI3;

typedef struct _STI3 {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;          /* 5 = Waiting */
    ULONG WaitReason;           /* 6 = UserRequest */
} STI3, *PSTI3;

typedef struct _MBINF {
    PVOID Base;
    PVOID AllocBase;
    ULONG AllocProt;
    ULONG Pad0;
    SIZE_T Size;
    ULONG State;
    ULONG Protect;
    ULONG Type;
    ULONG Pad1;
} MBINF;

/* ---------------- logging ---------------- */
static VOID WriteA(PCWSTR file, PCSTR text, ULONG len)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    RtlInitUnicodeString(&p, file);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &io, NULL,
                                 FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0))) return;
    ZwWriteFile(h, NULL, NULL, NULL, &io, (PVOID)text, len, NULL, NULL);
    ZwFlushBuffersFile(h, &io);
    ZwClose(h);
}
static VOID KLog(PCSTR t)
{
    size_t n = 0;
    RtlStringCchLengthA(t, 2048, &n);
    WriteA(LOG_FILE, t, (ULONG)n);
}
static VOID KLogF(PCSTR f, ...)
{
    CHAR b[1024]; va_list ap;
    va_start(ap, f);
    RtlStringCchVPrintfA(b, sizeof(b), f, ap);
    va_end(ap);
    KLog(b);
}

/* ---------------- job ---------------- */
typedef struct _JOB {
    ULONG  Pid;
    WCHAR  Name[128];
    ULONG  Phase;
    ULONG  Samples;
    ULONG  Gap;
    ULONG  Limit;
    ULONG  UseIpi;
    ULONG  Retries;
    ULONG  RetryGap;
    WCHAR  Dll[260];
    WCHAR  Pic[260];
    WCHAR  Wnd[260];
    ULONG  WndInst;
    ULONG  WndProcOff;
    ULONG  WndSwap;
    WCHAR  WndClass[4][64];
    ULONG  WndClassCount;
    ULONG  ImpDump;
    ULONG  VtScan;
    ULONG  VtTrial;
    ULONG  VtSlot;
    ULONG  VtWait;
    ULONG  FactoryMode;
    ULONG  SettleMs;
    ULONG  PollMs;
    ULONG  PatHook;
    ULONG  PatIndex;
    ULONG  QiTest;
    ULONG  CacheScan;
    ULONG  CacheVal;
    WCHAR  QiPayload[260];
    WCHAR  VtMod[64];
    WCHAR  IatMod[64];
    WCHAR  IatDll[64];
    WCHAR  IatApi[64];
    WCHAR  HookMod[64];
    ULONG  HookRva;
    ULONG  HookN;
    UCHAR  HookOrig[32];
    ULONG  HookForce;
    U64    Pin;
} JOB;

static VOID SleepMs(ULONG ms)
{
    LARGE_INTEGER d;
    d.QuadPart = -((LONGLONG)ms * 10000LL);
    KeDelayExecutionThread(KernelMode, FALSE, &d);
}

static ULONG ParseULong(PCSTR s, PCSTR end)
{
    ULONG v = 0;
    while (s < end && (*s < '0' || *s > '9')) s++;
    while (s < end && *s >= '0' && *s <= '9') { v = v * 10 + (ULONG)(*s - '0'); s++; }
    return v;
}
static U64 ParseHex(PCSTR s, PCSTR end)
{
    U64 v = 0;
    while (s < end && *s != '0') s++;
    if (s + 1 < end && (s[1] == 'x' || s[1] == 'X')) s += 2;
    for (; s < end; s++) {
        CHAR c = *s;
        if (c >= '0' && c <= '9') v = (v << 4) | (U64)(c - '0');
        else if (c >= 'a' && c <= 'f') v = (v << 4) | (U64)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v = (v << 4) | (U64)(c - 'A' + 10);
        else break;
    }
    return v;
}

static NTSTATUS ReadJob(PUCHAR buf, ULONG cap, PULONG outLen)
{
    UNICODE_STRING path; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb; HANDLE h;
    FILE_STANDARD_INFORMATION fsi; LARGE_INTEGER off; NTSTATUS st;

    RtlInitUnicodeString(&path, JOB_FILE);
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&h, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) return st;
    st = ZwQueryInformationFile(h, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(st) || fsi.EndOfFile.QuadPart <= 0 || fsi.EndOfFile.QuadPart > cap) {
        ZwClose(h);
        return STATUS_INVALID_PARAMETER;
    }
    off.QuadPart = 0;
    st = ZwReadFile(h, NULL, NULL, NULL, &iosb, buf, (ULONG)fsi.EndOfFile.QuadPart, &off, NULL);
    ZwClose(h);
    if (!NT_SUCCESS(st)) return st;
    *outLen = (ULONG)fsi.EndOfFile.QuadPart;
    buf[*outLen] = 0;
    return STATUS_SUCCESS;
}

/* exact key match: "wnd" must not swallow "wndinst" / "wndproc" */
static BOOLEAN StartsWith(PCSTR p, PCSTR end, PCSTR key)
{
    ULONG n = 0;
    while (key[n]) n++;
    if ((ULONG)(end - p) != n) return FALSE;
    while (*key) { if (*p++ != *key++) return FALSE; }
    return TRUE;
}

static VOID ParseJob(PUCHAR buf, ULONG len, JOB* j)
{
    PCSTR p = (PCSTR)buf;
    PCSTR end = (PCSTR)buf + len;

    RtlZeroMemory(j, sizeof(*j));
    j->Phase = 1; j->Samples = 5; j->Gap = 150; j->Limit = 800; j->UseIpi = 1;
    j->Retries = 40; j->RetryGap = 8000;

    while (p < end) {
        PCSTR lineEnd = p, eq;
        while (lineEnd < end && *lineEnd != '\r' && *lineEnd != '\n') lineEnd++;
        eq = p;
        while (eq < lineEnd && *eq != '=') eq++;
        if (eq < lineEnd && eq > p) {
            PCSTR v = eq + 1;
            if (StartsWith(p, eq, "pid")) j->Pid = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "phase")) j->Phase = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "samples")) j->Samples = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "gap")) j->Gap = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "limit")) j->Limit = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "slot")) j->Pin = ParseHex(v, lineEnd);
            else if (StartsWith(p, eq, "wnd")) {
                ULONG k = 0;
                while (v + k < lineEnd && k < 258) { j->Wnd[k] = (WCHAR)v[k]; k++; }
                j->Wnd[k] = 0;
            }
            else if (StartsWith(p, eq, "wndinst")) j->WndInst = (ULONG)ParseHex(v, lineEnd);
            else if (StartsWith(p, eq, "wndproc")) j->WndProcOff = (ULONG)ParseHex(v, lineEnd);
            else if (StartsWith(p, eq, "wndswap")) j->WndSwap = (ULONG)ParseHex(v, lineEnd);
            else if (StartsWith(p, eq, "wndclass")) {
                ULONG k = 0, n = 0;
                j->WndClassCount = 0;
                while (v < lineEnd && j->WndClassCount < 4) {
                    k = 0;
                    while (v < lineEnd && *v != ',' && k < 62) { j->WndClass[j->WndClassCount][k] = (WCHAR)*v; v++; k++; }
                    j->WndClass[j->WndClassCount][k] = 0;
                    if (k) j->WndClassCount++;
                    if (v < lineEnd && *v == ',') v++;
                }
                (void)n;
            }
            else if (StartsWith(p, eq, "impdump")) j->ImpDump = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "vtscan")) j->VtScan = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "vttrial")) j->VtTrial = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "vtslot")) j->VtSlot = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "vtwait")) j->VtWait = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "pathook")) j->PatHook = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "factory")) j->FactoryMode = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "settlems")) j->SettleMs = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "pollms")) j->PollMs = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "patindex")) j->PatIndex = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "qitest")) j->QiTest = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "cachescan")) j->CacheScan = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "cacheval")) j->CacheVal = (ULONG)ParseHex(v, lineEnd);
            else if (StartsWith(p, eq, "qipayload")) {
                ULONG k = 0;
                while (v + k < lineEnd && k < 258) { j->QiPayload[k] = (WCHAR)v[k]; k++; }
                j->QiPayload[k] = 0;
            }
            else if (StartsWith(p, eq, "vtmod")) {
                ULONG k = 0;
                while (v + k < lineEnd && k < 62) { j->VtMod[k] = (WCHAR)v[k]; k++; }
                j->VtMod[k] = 0;
            }
            else if (StartsWith(p, eq, "iatmod") || StartsWith(p, eq, "iatdll") || StartsWith(p, eq, "iatapi")) {
                WCHAR* dst = StartsWith(p, eq, "iatmod") ? j->IatMod
                           : StartsWith(p, eq, "iatdll") ? j->IatDll : j->IatApi;
                ULONG k = 0;
                while (v + k < lineEnd && k < 62) { dst[k] = (WCHAR)v[k]; k++; }
                dst[k] = 0;
            }
            else if (StartsWith(p, eq, "hookmod")) {
                ULONG k = 0;
                while (v + k < lineEnd && k < 62) { j->HookMod[k] = (WCHAR)v[k]; k++; }
                j->HookMod[k] = 0;
            }
            else if (StartsWith(p, eq, "hookrva")) j->HookRva = (ULONG)ParseHex(v, lineEnd);
            else if (StartsWith(p, eq, "hookn")) j->HookN = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "hookforce")) j->HookForce = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "hookorig")) {
                ULONG n = 0;
                while (v < lineEnd && n < 32) {
                    ULONG hi, lo;
                    while (v < lineEnd && (*v == ' ' || *v == ',')) v++;
                    if (v + 1 >= lineEnd) break;
                    hi = (v[0] >= '0' && v[0] <= '9') ? (ULONG)(v[0] - '0') : (ULONG)((v[0] | 0x20) - 'a' + 10);
                    lo = (v[1] >= '0' && v[1] <= '9') ? (ULONG)(v[1] - '0') : (ULONG)((v[1] | 0x20) - 'a' + 10);
                    j->HookOrig[n++] = (UCHAR)((hi << 4) | lo);
                    v += 2;
                }
            }
            else if (StartsWith(p, eq, "pic")) {
                ULONG k = 0;
                while (v + k < lineEnd && k < 258) { j->Pic[k] = (WCHAR)v[k]; k++; }
                j->Pic[k] = 0;
            }
            else if (StartsWith(p, eq, "dll")) {
                ULONG k = 0;
                while (v + k < lineEnd && k < 258) { j->Dll[k] = (WCHAR)v[k]; k++; }
                j->Dll[k] = 0;
            }
            else if (StartsWith(p, eq, "retries")) j->Retries = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "retrygap")) j->RetryGap = ParseULong(v, lineEnd);
            else if (StartsWith(p, eq, "flush")) j->UseIpi = !(v < lineEnd && (*v == 'l' || *v == 'L'));
            else if (StartsWith(p, eq, "name")) {
                ULONG k = 0;
                while (v + k < lineEnd && k < 126) { j->Name[k] = (WCHAR)v[k]; k++; }
                j->Name[k] = 0;
            }
        }
        p = lineEnd;
        while (p < end && (*p == '\r' || *p == '\n')) p++;
    }
}

/* ---------------- process ---------------- */
static ULONG FindPid(PCWSTR name, LARGE_INTEGER* outCreate)
{
    ULONG size = 1 << 20, ret = 0, result = 0;
    PVOID buf; NTSTATUS st; UNICODE_STRING want;

    buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK');
    if (!buf) return 0;
    st = ZwQuerySystemInformation(5, buf, size, &ret);
    if (st == STATUS_INFO_LENGTH_MISMATCH && ret > size) {
        ExFreePoolWithTag(buf, 'pmiK');
        size = ret + 0x1000;
        buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK');
        if (!buf) return 0;
        st = ZwQuerySystemInformation(5, buf, size, &ret);
    }
    if (!NT_SUCCESS(st)) { ExFreePoolWithTag(buf, 'pmiK'); return 0; }

    RtlInitUnicodeString(&want, name);
    {
        PUCHAR p = (PUCHAR)buf;
        for (;;) {
            PSPI3 e = (PSPI3)p;
            if (e->ImageName.Buffer && e->ImageName.Length) {
                UNICODE_STRING u = e->ImageName;
                if (RtlEqualUnicodeString(&u, &want, TRUE)) {
                    result = (ULONG)(ULONG_PTR)e->UniqueProcessId;
                    if (outCreate) *outCreate = e->CreateTime;
                    break;
                }
            }
            if (!e->NextEntryOffset) break;
            p += e->NextEntryOffset;
        }
    }
    ExFreePoolWithTag(buf, 'pmiK');
    return result;
}

/* threads in Waiting/UserRequest -- safest to grab a user context from */
static ULONG GetWaitingThreads(ULONG pid, ULONG* tids, ULONG max, BOOLEAN verbose)
{
    ULONG size = 1 << 20, ret = 0, count = 0;
    PVOID buf; NTSTATUS st;
    PUCHAR p;

    buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK');
    if (!buf) return 0;
    st = ZwQuerySystemInformation(5, buf, size, &ret);
    if (st == STATUS_INFO_LENGTH_MISMATCH && ret > size) {
        ExFreePoolWithTag(buf, 'pmiK');
        size = ret + 0x1000;
        buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'pmiK');
        if (!buf) return 0;
        st = ZwQuerySystemInformation(5, buf, size, &ret);
    }
    if (!NT_SUCCESS(st)) { ExFreePoolWithTag(buf, 'pmiK'); return 0; }

    for (p = (PUCHAR)buf; ; ) {
        PSPI3 e = (PSPI3)p;
        if ((ULONG)(ULONG_PTR)e->UniqueProcessId == pid) {
            ULONG i;
            PSTI3 t = (PSTI3)(p + 0x100);
            KLogF("[sc3] spi threads=%lu\n", e->NumberOfThreads);
            if (e->NumberOfThreads < 0x1000) {
                for (i = 0; i < e->NumberOfThreads; i++, t++) {
                    ULONG tid = (ULONG)(ULONG_PTR)t->ClientId.UniqueThread;
                    if (verbose && i < 40)
                        KLogF("[sc3]  th tid=%lu state=%lu reason=%lu start=%p\n", tid,
                              t->ThreadState, t->WaitReason, t->StartAddress);
                    if (t->ThreadState == 5 && (t->WaitReason == 4 || t->WaitReason == 6) && tid && count < max) {
                        tids[count] = tid;
                        count++;
                    }
                }
            }
            break;
        }
        if (!e->NextEntryOffset) break;
        p += e->NextEntryOffset;
    }
    ExFreePoolWithTag(buf, 'pmiK');
    return count;
}

/* ---------------- pte ---------------- */
static ULONG64 FindNtBase(VOID)
{
    UNICODE_STRING nm, want; LIST_ENTRY* head; LIST_ENTRY* cur;
    RtlInitUnicodeString(&nm, L"PsLoadedModuleList");
    head = (LIST_ENTRY*)MmGetSystemRoutineAddress(&nm);
    if (!head) return 0;
    RtlInitUnicodeString(&want, L"ntoskrnl.exe");
    for (cur = head->Flink; cur != head && cur; cur = cur->Flink) {
        PUCHAR e = (PUCHAR)cur; UNICODE_STRING u;
        u.Length = *(USHORT*)(e + 0x58); u.MaximumLength = u.Length; u.Buffer = *(PWCH*)(e + 0x60);
        if (u.Buffer && u.Length && RtlEqualUnicodeString(&u, &want, TRUE)) return *(ULONG64*)(e + 0x30);
    }
    return 0;
}

/* MmPteBase is randomized per boot (Win11): read the movabs rsi, imm64 inside
   MmIsAddressValid's inner function (this build: rva 0x2AB5A0) */
static ULONG64 ReadPteBase(ULONG64 ntBase)
{
    PUCHAR p = (PUCHAR)(ULONG_PTR)(ntBase + 0x2AB5A0);
    ULONG i;
    for (i = 0; i + 10 < 0x120; i++) {
        if (p[i] == 0x48 && p[i + 1] == 0xBE) {
            ULONG64 v = *(ULONG64*)(p + i + 2);
            if ((v & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL) return v;
        }
    }
    return 0;
}

static ULONG_PTR NTAPI FlushRoutine(ULONG_PTR ctx)
{
    __invlpg((PVOID)ctx);
    return ctx;
}

static ULONG64 g_PteBase = 0;
static ULONG64 g_skipLo = 0, g_skipHi = 0;
static ULONG g_UseIpi = 0;

static VOID FlushTlb(U64 va)
{
    __invlpg((PVOID)(ULONG_PTR)va);
    if (g_UseIpi) KeIpiGenericCall(FlushRoutine, (ULONG_PTR)va);
}

static BOOLEAN PteLoad(U64 va, U64* outVal, U64* outPteAddr)
{
    U64 idx = (va >> 12) & 0xFFFFFFFFFULL;
    U64 pteAddr = g_PteBase + (idx << 3);
    U64 pdeAddr = g_PteBase + (((va >> 12) & ~0x1FFULL) << 3);
    U64 val;

    if (!MmIsAddressValid((PVOID)(ULONG_PTR)pdeAddr)) return FALSE;
    if ((*(U64*)(ULONG_PTR)pdeAddr & 0x80) != 0) return FALSE;   /* 2MB large page */
    if (!MmIsAddressValid((PVOID)(ULONG_PTR)pteAddr)) return FALSE;
    val = *(U64*)(ULONG_PTR)pteAddr;
    if ((val & 1) == 0) return FALSE;
    *outVal = val;
    *outPteAddr = pteAddr;
    return TRUE;
}

/* ---------------- memory rw ---------------- */
static NTSTATUS MemRead(PEPROCESS proc, U64 va, PVOID dst, SIZE_T len)
{
    SIZE_T done = 0;
    return MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)va, PsGetCurrentProcess(), dst, len, KernelMode, &done);
}
static NTSTATUS MemWrite(PEPROCESS proc, U64 va, PVOID src, SIZE_T len)
{
    SIZE_T done = 0;
    return MmCopyVirtualMemory(PsGetCurrentProcess(), src, proc, (PVOID)(ULONG_PTR)va, len, KernelMode, &done);
}

/* ---------------- local file helpers ---------------- */
static NTSTATUS ReadFileAll(PCWSTR path, PVOID buf, ULONG cap, PULONG outLen)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb; HANDLE h;
    FILE_STANDARD_INFORMATION fsi; LARGE_INTEGER off; NTSTATUS st;

    RtlInitUnicodeString(&p, path);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&h, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) return st;
    st = ZwQueryInformationFile(h, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(st) || fsi.EndOfFile.QuadPart <= 0 || fsi.EndOfFile.QuadPart > cap) { ZwClose(h); return STATUS_INVALID_PARAMETER; }
    off.QuadPart = 0;
    st = ZwReadFile(h, NULL, NULL, NULL, &iosb, buf, (ULONG)fsi.EndOfFile.QuadPart, &off, NULL);
    ZwClose(h);
    if (!NT_SUCCESS(st)) return st;
    *outLen = (ULONG)fsi.EndOfFile.QuadPart;
    return STATUS_SUCCESS;
}

static BOOLEAN FileExists(PCWSTR path)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb; HANDLE h; NTSTATUS st;

    RtlInitUnicodeString(&p, path);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&h, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) return FALSE;
    ZwClose(h);
    return TRUE;
}

/* ---------------- target side: modules / exports / unhook ---------------- */
static U64 TargetModuleBase(PEPROCESS proc, PCWSTR name)
{
    KAPC_STATE apc; PPEB peb; PVOID ldr; LIST_ENTRY* head; LIST_ENTRY* cur; U64 result = 0;
    UNICODE_STRING want;

    KeStackAttachProcess(proc, &apc);
    peb = (PPEB)PsGetProcessPeb(proc);
    if (peb && (U64)(ULONG_PTR)peb > 0x10000 && (U64)(ULONG_PTR)peb < 0x00007FFFFFFF0000ULL) {
        ldr = *(PVOID*)((PUCHAR)peb + 0x18);
        if (ldr && (U64)(ULONG_PTR)ldr > 0x10000 && (U64)(ULONG_PTR)ldr < 0x00007FFFFFFF0000ULL) {
            ULONG guard = 0;
            U64 cursor;
            head = (LIST_ENTRY*)((PUCHAR)ldr + 0x10);
            RtlInitUnicodeString(&want, name);
            cursor = (U64)(ULONG_PTR)head->Flink;
            while (guard++ < 512) {
                PUCHAR e;
                UNICODE_STRING bn;

                if (cursor == (U64)(ULONG_PTR)head) break;
                /* the loader mutates this list while we look at it: never trust a link */
                if (cursor < 0x10000 || cursor >= 0x00007FFFFFFF0000ULL || (cursor & 3)) break;
                e = (PUCHAR)(ULONG_PTR)cursor;
                bn.Length = *(USHORT*)(e + 0x58);
                bn.MaximumLength = bn.Length;
                bn.Buffer = *(PWCH*)(e + 0x60);
                if (bn.Length > 0x200 || (bn.Length & 1)) break;
                if (bn.Length && ((U64)(ULONG_PTR)bn.Buffer < 0x10000 ||
                                  (U64)(ULONG_PTR)bn.Buffer >= 0x00007FFFFFFF0000ULL))
                    break;
                if (bn.Length && RtlEqualUnicodeString(&bn, &want, TRUE)) {
                    result = *(U64*)(e + 0x30);
                    break;
                }
                cursor = (U64)(ULONG_PTR)((LIST_ENTRY*)(ULONG_PTR)cursor)->Flink;
            }
        }
    }
    KeUnstackDetachProcess(&apc);
    return result;
}

static U64 TargetExport(U64 modBase, PCSTR wanted)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_EXPORT_DIRECTORY pexp;
    ULONG* names; USHORT* ords; ULONG* funcs;
    ULONG i;

    if (!modBase) return 0;
    dos = (PIMAGE_DOS_HEADER)(ULONG_PTR)modBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    nt = (PIMAGE_NT_HEADERS)((PUCHAR)(ULONG_PTR)modBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    if (!nt->OptionalHeader.DataDirectory[0].VirtualAddress) return 0;
    pexp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)(ULONG_PTR)modBase + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    names = (ULONG*)((PUCHAR)(ULONG_PTR)modBase + pexp->AddressOfNames);
    ords = (USHORT*)((PUCHAR)(ULONG_PTR)modBase + pexp->AddressOfNameOrdinals);
    funcs = (ULONG*)((PUCHAR)(ULONG_PTR)modBase + pexp->AddressOfFunctions);
    if (pexp->NumberOfNames > 0x10000) return 0;
    for (i = 0; i < pexp->NumberOfNames; i++) {
        PCSTR a = (PCSTR)((PUCHAR)(ULONG_PTR)modBase + names[i]);
        PCSTR b = wanted;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0) return modBase + funcs[ords[i]];
    }
    return 0;
}

/* resolve base + export inside the target context: touching user VAs while
   detached is what caused the 0x1E (p4 = target kernel32 base) */
static U64 TargetResolveExport(PEPROCESS proc, PCWSTR modName, PCSTR api)
{
    KAPC_STATE apc;
    U64 base = 0, fn = 0;

    KeStackAttachProcess(proc, &apc);
    base = TargetModuleBase(proc, modName);
    if (base) fn = TargetExport(base, api);
    KeUnstackDetachProcess(&apc);
    return fn;
}

/* the 8 user-mode inline hooks javelin installs (see doc section 15) */
typedef struct _UPATCH { ULONG Which; ULONG Rva; UCHAR Orig[8]; } UPATCH;
static const UPATCH g_upatches[] = {
    { 0, 0x1666D0, { 0x4C,0x8B,0xD1,0xB8,0x18,0x00,0x00,0x00 } },   /* NtAllocateVirtualMemory */
    { 0, 0x166DD0, { 0x4C,0x8B,0xD1,0xB8,0x50,0x00,0x00,0x00 } },   /* NtProtectVirtualMemory  */
    { 0, 0x1668D0, { 0x4C,0x8B,0xD1,0xB8,0x28,0x00,0x00,0x00 } },   /* NtMapViewOfSection      */
    { 0, 0x03E550, { 0x4C,0x8B,0xDC,0x49,0x89,0x5B,0x10,0x56 } },   /* LdrLoadDll              */
    { 1, 0x03F6C0, { 0x48,0xFF,0x25,0x21,0xBD,0x04,0x00,0xCC } },   /* LoadLibraryW            */
    { 1, 0x03C7B0, { 0x48,0xFF,0x25,0xF1,0xEB,0x04,0x00,0xCC } },   /* LoadLibraryExW          */
    { 1, 0x033160, { 0x48,0xFF,0x25,0x11,0x85,0x05,0x00,0xCC } },   /* VirtualAlloc            */
    { 1, 0x038460, { 0x48,0xFF,0x25,0x29,0x32,0x05,0x00,0xCC } },   /* VirtualProtect          */
};

/* restore original prologues through the pte rw bit (same trick as unhook4) */
static ULONG UnhookTarget(PEPROCESS proc)
{
    KAPC_STATE apc; U64 ntBase = 0, k32Base = 0; ULONG i, ok = 0, skip = 0, fail = 0;

    /* resolve first (each call attaches on its own), then attach once for the
       pte + code writes -- avoids nesting attach on the same process */
    ntBase = TargetModuleBase(proc, L"ntdll.dll");
    k32Base = TargetModuleBase(proc, L"kernel32.dll");
    KLogF("[sc3] unhook bases ntdll=0x%llX k32=0x%llX\n", ntBase, k32Base);

    KeStackAttachProcess(proc, &apc);

    for (i = 0; i < RTL_NUMBER_OF(g_upatches); i++) {
        U64 va = (g_upatches[i].Which == 0 ? ntBase : k32Base) + g_upatches[i].Rva;
        U64 pteVal = 0, pteAddr = 0;
        PUCHAR code;

        if (!va || !PteLoad(va, &pteVal, &pteAddr)) { fail++; continue; }
        *(U64*)(ULONG_PTR)pteAddr = pteVal | 2;
        __invlpg((PVOID)(ULONG_PTR)va);
        code = (PUCHAR)(ULONG_PTR)va;
        if (code[0] != 0xE9) {
            skip++;
        } else {
            RtlCopyMemory(code, g_upatches[i].Orig, 8);
            if (code[0] == g_upatches[i].Orig[0] && code[1] == g_upatches[i].Orig[1]) ok++;
            else fail++;
        }
        *(U64*)(ULONG_PTR)pteAddr = pteVal;
        __invlpg((PVOID)(ULONG_PTR)va);
    }
    KeUnstackDetachProcess(&apc);
    KLogF("[sc3] unhook ok=%lu skip=%lu fail=%lu\n", ok, skip, fail);
    return ok;
}

/* ---------------- regions ---------------- */
#define MAX_REG 512
typedef struct _REG { U64 Base; U64 Size; } REG;

static ULONG EnumRW(PEPROCESS proc, REG* out, ULONG max, ULONG limit)
{
    KAPC_STATE apc; U64 addr = 0x10000; ULONG count = 0, scanned = 0;

    KeStackAttachProcess(proc, &apc);
    while (addr < 0x00007FFFFFFF0000ULL && scanned < limit && count < max) {
        MBINF m; SIZE_T r = 0; NTSTATUS st;
        RtlZeroMemory(&m, sizeof(m));
        st = ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)(ULONG_PTR)addr, 0, &m, sizeof(m), &r);
        if (!NT_SUCCESS(st) || !m.Size) { addr += 0x10000; continue; }
        if (m.State == 0x1000 && (m.Protect & 0xFF) == 0x04 && m.Type == 0x20000 && m.Size >= 0x8000) {
            out[count].Base = (U64)m.Base;
            out[count].Size = (m.Size > 0x80000) ? 0x80000 : m.Size;
            count++;
            scanned++;
        }
        addr = (U64)m.Base + m.Size;
    }
    KeUnstackDetachProcess(&apc);
    return count;
}

typedef struct _SLOT { U64 Va; U64 Page; ULONG Off; ULONG Kind; ULONG Score; BOOLEAN Verified; } SLOT;

/* ---------------- canary ---------------- */
static const UCHAR g_canary[16] = { 0x5C,0xC0,0xDE,0x5C,0xC0,0xDE,0xA5,0x5A,
                                    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88 };

static BOOLEAN CanaryCheck(PEPROCESS proc, SLOT* s)
{
    UCHAR back[16];
    ULONG round, ok = 0;

    for (round = 0; round < 4; round++) {
        UCHAR orig[16];
        if (!NT_SUCCESS(MemRead(proc, s->Va, orig, 16))) return FALSE;
        if (!NT_SUCCESS(MemWrite(proc, s->Va, (PVOID)g_canary, 16))) return FALSE;
        SleepMs(300);
        if (!NT_SUCCESS(MemRead(proc, s->Va, back, 16))) return FALSE;
        if (RtlCompareMemory(back, g_canary, 16) == 16) ok++;
        MemWrite(proc, s->Va, orig, 16);
        SleepMs(100);
    }
    s->Verified = (ok == 4);
    return s->Verified;
}

/* ---------------- shellcode ----------------
   slot+0x00 : 31 bytes
   slot+0x40 : data[0] counter, data[8] magic, data[0x10] return rip
   push rax / movabs rax,data / inc [rax] / mov qword [rax+8],magic /
   mov rax,[rax+0x10] / xchg rax,[rsp] / ret
*/
#define SC_LEN   31
#define DATA_OFF 0x40
#define MAGIC32  0x5C0DE5C0u

static ULONG BuildShellcode(UCHAR* sc, U64 dataVa)
{
    ULONG n = 0;
    sc[n++] = 0x50;
    sc[n++] = 0x48; sc[n++] = 0xB8;
    *(U64*)(sc + n) = dataVa; n += 8;
    sc[n++] = 0x48; sc[n++] = 0xFF; sc[n++] = 0x00;
    sc[n++] = 0x48; sc[n++] = 0xC7; sc[n++] = 0x40; sc[n++] = 0x08;
    *(ULONG*)(sc + n) = MAGIC32; n += 4;
    sc[n++] = 0x48; sc[n++] = 0x8B; sc[n++] = 0x40; sc[n++] = 0x10;
    sc[n++] = 0x48; sc[n++] = 0x87; sc[n++] = 0x04; sc[n++] = 0x24;
    sc[n++] = 0xC3;
    return n;
}

/* APC variant: inc counter, store magic, restore rax, return to KiUserApcDispatcher */
static ULONG BuildApcShellcode(UCHAR* sc, U64 dataVa)
{
    ULONG n = 0;
    sc[n++] = 0x50;
    sc[n++] = 0x48; sc[n++] = 0xB8;
    *(U64*)(sc + n) = dataVa; n += 8;
    sc[n++] = 0x48; sc[n++] = 0xFF; sc[n++] = 0x00;
    sc[n++] = 0x48; sc[n++] = 0xC7; sc[n++] = 0x40; sc[n++] = 0x08;
    *(ULONG*)(sc + n) = MAGIC32; n += 4;
    sc[n++] = 0x58;
    sc[n++] = 0x31; sc[n++] = 0xC0;
    sc[n++] = 0xC3;
    return n;
}

/* loader: inc counter + magic (observable), then
   sub rsp,0x28 / mov rcx,path / mov rax,LoadLibraryW / call rax / add rsp,0x28 / ret */
static ULONG BuildLoaderShellcode(UCHAR* sc, U64 dataVa, U64 pathVa, U64 llwVa, U64 gleVa)
{
    ULONG n = 0;
    sc[n++] = 0x50;                                     /* push rax            */
    sc[n++] = 0x48; sc[n++] = 0xB8;
    *(U64*)(sc + n) = dataVa; n += 8;                   /* movabs rax, data    */
    sc[n++] = 0x48; sc[n++] = 0xFF; sc[n++] = 0x00;     /* inc qword [rax]     */
    sc[n++] = 0x48; sc[n++] = 0xC7; sc[n++] = 0x40; sc[n++] = 0x08;
    *(ULONG*)(sc + n) = MAGIC32; n += 4;                /* mov [rax+8], magic  */
    sc[n++] = 0x58;                                     /* pop rax             */
    sc[n++] = 0x48; sc[n++] = 0x83; sc[n++] = 0xEC; sc[n++] = 0x28;
    sc[n++] = 0x48; sc[n++] = 0xB9;
    *(U64*)(sc + n) = pathVa; n += 8;                   /* mov rcx, path       */
    sc[n++] = 0x48; sc[n++] = 0xB8;
    *(U64*)(sc + n) = llwVa; n += 8;                    /* mov rax, llw        */
    sc[n++] = 0xFF; sc[n++] = 0xD0;                     /* call rax            */
    sc[n++] = 0x49; sc[n++] = 0xBA;
    *(U64*)(sc + n) = dataVa; n += 8;                   /* movabs r10, data    */
    sc[n++] = 0x49; sc[n++] = 0x89; sc[n++] = 0x42; sc[n++] = 0x10;   /* [data+10]=hmod */
    sc[n++] = 0x48; sc[n++] = 0xB8;
    *(U64*)(sc + n) = gleVa; n += 8;                    /* mov rax, GetLastError */
    sc[n++] = 0xFF; sc[n++] = 0xD0;                     /* call rax            */
    sc[n++] = 0x49; sc[n++] = 0xBA;
    *(U64*)(sc + n) = dataVa; n += 8;
    sc[n++] = 0x49; sc[n++] = 0x89; sc[n++] = 0x42; sc[n++] = 0x18;   /* [data+18]=err */
    sc[n++] = 0x48; sc[n++] = 0x83; sc[n++] = 0xC4; sc[n++] = 0x28;
    sc[n++] = 0x31; sc[n++] = 0xC0;                     /* xor eax,eax         */
    sc[n++] = 0xC3;
    return n;
}

/* ---------------- thread hijack ---------------- */
#define CTX_FLAGS (CONTEXT_CONTROL | CONTEXT_INTEGER)

static NTSTATUS OpenThreadObject(ULONG tid, PETHREAD* thread, HANDLE* handle)
{
    NTSTATUS st;
    *thread = NULL;
    *handle = NULL;
    st = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)tid, thread);
    if (!NT_SUCCESS(st)) return st;
    st = ObOpenObjectByPointer(*thread, OBJ_KERNEL_HANDLE, NULL, THREAD_ALL_ACCESS,
                               *PsThreadType, KernelMode, handle);
    if (!NT_SUCCESS(st)) { ObDereferenceObject(*thread); *thread = NULL; return st; }
    return STATUS_SUCCESS;
}

/* user-mode APC into an existing thread: no new thread, no context juggling.
   The thread must reach an alertable wait (SleepEx / WaitForSingleObjectEx). */
static VOID NTAPI ApcKernelRoutine(PVOID Apc, PVOID Normal, PVOID NormalContext,
                                   PVOID SystemArg1, PVOID SystemArg2)
{
    UNREFERENCED_PARAMETER(Normal);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArg1);
    UNREFERENCED_PARAMETER(SystemArg2);
    if (Apc) ExFreePoolWithTag(Apc, 'apcS');
}

static BOOLEAN QueueUserApc(ULONG tid, U64 scVa, U64 ctx)
{
    PETHREAD thread = NULL;
    PSC_KAPC apc;
    NTSTATUS st;
    BOOLEAN queued;

    st = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)tid, &thread);
    if (!NT_SUCCESS(st)) return FALSE;

    apc = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(SC_KAPC), 'apcS');
    if (!apc) { ObDereferenceObject(thread); return FALSE; }

    KeInitializeApc(apc, thread, 1 /* OriginalApcEnvironment */, (PVOID)ApcKernelRoutine,
                    NULL, (PVOID)(ULONG_PTR)scVa, UserMode, (PVOID)(ULONG_PTR)ctx);
    queued = KeInsertQueueApc(apc, NULL, NULL, 0);
    KLogF("[sc3]  tid=%lu apc=%p queued=%d\n", tid, apc, (int)queued);
    if (!queued) ExFreePoolWithTag(apc, 'apcS');
    ObDereferenceObject(thread);
    return queued;
}
/* ---------------- main path ---------------- */
typedef struct _SCAN { SLOT Slots[16]; ULONG Total; ULONG Verified; } SCAN;

/* Only pages that are fully zero and stable across two samples are used.
   Churning pages are never written: canary writes into them took the game down. */
static ULONG FindZeroSlots(PEPROCESS proc, REG* regs, ULONG regCount, SLOT* out, ULONG max)
{
    UCHAR* a = NULL;
    UCHAR* b = NULL;
    ULONG i, count = 0;

    a = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x1000, 'zroS');
    b = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x1000, 'zroS');
    if (!a || !b) {
        if (a) ExFreePoolWithTag(a, 'zroS');
        if (b) ExFreePoolWithTag(b, 'zroS');
        return 0;
    }

    for (i = 0; i < regCount && count < max; i++) {
        U64 sz = regs[i].Size;
        ULONG npages = (ULONG)(sz >> 12);
        ULONG idxs[24];
        ULONG nidx = 0, j2;

        if ((i & 31) == 0 && PsGetProcessExitStatus(proc) != STATUS_PENDING) break;
        if (npages == 0) continue;
        /* spread the probes over the whole region: a hot allocation usually has
           only a few pages in use, the rest stays zero */
        for (j2 = 0; j2 < 16 && j2 < npages; j2++) {
            ULONG idx = (npages <= 16) ? j2 : (ULONG)((U64)j2 * (npages - 1) / 15);
            idxs[nidx++] = idx;
        }

        for (j2 = 0; j2 < nidx && count < max; j2++) {
            U64 base = regs[i].Base + (U64)idxs[j2] * 0x1000;
            SIZE_T done = 0;
            ULONG k, zeros = 0;

            if (!NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)base, PsGetCurrentProcess(),
                                                a, 0x1000, KernelMode, &done)) || done != 0x1000)
                continue;
            for (k = 0; k < 0x1000; k++) if (a[k] == 0) zeros++;
            if (zeros != 0x1000) continue;

            SleepMs(40);
            done = 0;
            if (!NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)base, PsGetCurrentProcess(),
                                                b, 0x1000, KernelMode, &done)) || done != 0x1000)
                continue;
            if (RtlCompareMemory(a, b, 0x1000) != 0x1000) continue;

            out[count].Va = base + 0x800;
            out[count].Page = base;
            out[count].Off = 0x800;
            out[count].Kind = 4;
            out[count].Score = 100;
            out[count].Verified = FALSE;
            KLogF("[sc3] zero page 0x%llX size=0x%llX\n", base, regs[i].Size);
            count++;
        }
    }
    ExFreePoolWithTag(a, 'zroS');
    ExFreePoolWithTag(b, 'zroS');
    return count;
}
static VOID ScanOnce(PEPROCESS proc, JOB* j, SCAN* s, ULONG canaryLimit)
{
    REG* regs;
    ULONG regCount, i, verified = 0;

    s->Total = 0;
    RtlZeroMemory(s->Slots, sizeof(s->Slots));

    regs = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(REG) * MAX_REG, 'regS');
    if (!regs) { KLog("[sc3] pool alloc failed\n"); return; }

    regCount = EnumRW(proc, regs, MAX_REG, j->Limit);
    KLogF("[sc3] rw regions=%lu\n", regCount);

    s->Total = FindZeroSlots(proc, regs, regCount, s->Slots, 8);
    KLogF("[sc3] candidate slots=%lu\n", s->Total);

    for (i = 0; i < s->Total && i < canaryLimit; i++) {
        BOOLEAN ok;
        if (j->Pin != 0 && s->Slots[i].Va != j->Pin && s->Slots[i].Page != (j->Pin & ~0xFFFULL)) continue;
        ok = CanaryCheck(proc, &s->Slots[i]);
        KLogF("[sc3] slot 0x%llX (page=0x%llX kind=%lu) canary=%s\n",
              s->Slots[i].Va, s->Slots[i].Page, s->Slots[i].Kind, ok ? "OK" : "DEAD");
        if (ok) verified++;
    }
    s->Verified = verified;
    KLogF("[sc3] canary ok=%lu/%lu\n", verified, s->Total);

    ExFreePoolWithTag(regs, 'regS');
}
static BOOLEAN DoInject(PEPROCESS proc, JOB* j, SCAN* s)
{
    KAPC_STATE apc;
    SLOT* best = NULL;
    U64 scVa, dataVa, pteVal = 0, pteAddr = 0;
    BOOLEAN pteOk = FALSE, done = FALSE;
    UCHAR sc[64], orig[0x100];
    ULONG i, scLen, tCount;
    ULONG tids[16];
    ULONG seen[32], seenCount = 0;
    U64 ctx = 0;
    UCHAR picHead[4];

    picHead[0] = picHead[1] = picHead[2] = picHead[3] = 0;
    for (i = 0; i < s->Total; i++)
        if (s->Slots[i].Verified && (!best || s->Slots[i].Score > best->Score)) best = &s->Slots[i];
    if (!best) return FALSE;

    scVa = best->Va;
    dataVa = best->Va + DATA_OFF;
    RtlZeroMemory(sc, sizeof(sc));
    if (j->Pic[0]) {
        UCHAR* blob = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x2000, 'picS');
        UCHAR* tbl = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x400, 'tblS');
        ULONG blen = 0;

        if (!blob || !tbl) {
            if (blob) ExFreePoolWithTag(blob, 'picS');
            if (tbl) ExFreePoolWithTag(tbl, 'tblS');
            return FALSE;
        }
        {
            WCHAR full[300];
            NTSTATUS rst;
            RtlStringCchCopyW(full, RTL_NUMBER_OF(full), L"\\??\\");
            RtlStringCchCatW(full, RTL_NUMBER_OF(full), j->Pic);
            rst = ReadFileAll(full, blob, 0x2000, &blen);
            if (!NT_SUCCESS(rst) || blen < 16 || blen > 0x800) {
                KLogF("[sc3] read pic failed st=0x%X len=%lu\n", rst, blen);
                ExFreePoolWithTag(blob, 'picS');
                ExFreePoolWithTag(tbl, 'tblS');
                return FALSE;
            }
        }

        dataVa = scVa + 0x400;          /* table sits behind the code */
        RtlZeroMemory(tbl, 0x400);
        {
            U64 p1 = TargetResolveExport(proc, L"kernel32.dll", "CreateFileA");
            U64 p2 = TargetResolveExport(proc, L"kernel32.dll", "WriteFile");
            U64 p3 = TargetResolveExport(proc, L"kernel32.dll", "CloseHandle");
            U64 p4 = TargetResolveExport(proc, L"kernel32.dll", "GetCurrentProcessId");
            UNICODE_STRING outPath;

            *(U64*)(tbl + 0x18) = p1;
            *(U64*)(tbl + 0x20) = p2;
            *(U64*)(tbl + 0x28) = p3;
            *(U64*)(tbl + 0x30) = p4;
            RtlInitUnicodeString(&outPath, L"\\??\\C:\\Users\\Public\\pic-ok.txt");
            outPath.Buffer = L"C:\\Users\\Public\\pic-ok.txt";
            {   ANSI_STRING ansi;
                ansi.Buffer = (PCHAR)(tbl + 0x38);
                ansi.Length = 0; ansi.MaximumLength = 259;
                RtlUnicodeStringToAnsiString(&ansi, &outPath, FALSE);
            }
            ctx = dataVa;
            KLogF("[sc3] pic api cf=0x%llX wf=0x%llX ch=0x%llX gp=0x%llX\n", p1, p2, p3, p4);
        }

        picHead[0] = blob[0]; picHead[1] = blob[1]; picHead[2] = blob[2]; picHead[3] = blob[3];
        if (!NT_SUCCESS(MemWrite(proc, scVa, blob, blen))) { KLog("[sc3] write pic blob failed\n"); }
        if (!NT_SUCCESS(MemWrite(proc, dataVa, tbl, 0x400))) { KLog("[sc3] write pic table failed\n"); }
        ExFreePoolWithTag(blob, 'picS');
        ExFreePoolWithTag(tbl, 'tblS');
        scLen = 0;
        KLogF("[sc3] pic blob=%lu bytes at 0x%llX table=0x%llX\n", blen, scVa, dataVa);
    } else if (j->Dll[0]) {
        U64 pathVa = best->Va + 0x300;

        dataVa = best->Va + 0x180;
        U64 llw = TargetResolveExport(proc, L"kernel32.dll", "LoadLibraryW");
        U64 gle = TargetResolveExport(proc, L"kernel32.dll", "GetLastError");
        UCHAR path[520];
        ULONG n = 0;

        if (!llw || !gle) { KLogF("[sc3] resolve failed llw=0x%llX gle=0x%llX\n", llw, gle); return FALSE; }
        while (j->Dll[n] && n < 259) {
            path[n * 2] = (UCHAR)(j->Dll[n] & 0xFF);
            path[n * 2 + 1] = (UCHAR)((j->Dll[n] >> 8) & 0xFF);
            n++;
        }
        path[n * 2] = 0; path[n * 2 + 1] = 0;
        scLen = BuildLoaderShellcode(sc, dataVa, pathVa, llw, gle);
        KLogF("[sc3] loader slot=0x%llX path=0x%llX llw=0x%llX scLen=%lu\n", scVa, pathVa, llw, scLen);
        { U64 z[3]; z[0] = 0; z[1] = 0; z[2] = 0; MemWrite(proc, dataVa, z, 24); }
        if (!NT_SUCCESS(MemWrite(proc, pathVa, path, n * 2 + 2))) { KLog("[sc3] write dll path failed\n"); return FALSE; }
    } else {
        scLen = BuildApcShellcode(sc, dataVa);
        KLogF("[sc3] canary slot=0x%llX scLen=%lu data=0x%llX\n", scVa, scLen, dataVa);
    }

    /* javelin re-installs its user-mode hooks; unhook immediately before the
       loader runs, not 20s earlier during the scan */
    if (j->Dll[0]) {
        KLog("[sc3] unhook pass right before loader\n");
        UnhookTarget(proc);
    }

    if (!NT_SUCCESS(MemRead(proc, scVa, orig, sizeof(orig)))) { KLog("[sc3] backup orig bytes failed\n"); return FALSE; }

    KeStackAttachProcess(proc, &apc);
    pteOk = PteLoad(scVa, &pteVal, &pteAddr);
    KeUnstackDetachProcess(&apc);
    if (!pteOk) { KLog("[sc3] pte unavailable (not resident / large page), abort\n"); return FALSE; }
    KLogF("[sc3] pte=0x%llX val=0x%llX nx=%d rw=%d\n", pteAddr, pteVal,
          (int)((pteVal >> 63) & 1), (int)((pteVal >> 1) & 1));

    if (!NT_SUCCESS(MemWrite(proc, scVa, sc, scLen))) { KLog("[sc3] write shellcode failed\n"); return FALSE; }
    { U64 z[3]; z[0] = 0; z[1] = 0; z[2] = 0; MemWrite(proc, dataVa, z, 24); }

    KeStackAttachProcess(proc, &apc);
    *(U64*)(ULONG_PTR)pteAddr = pteVal & ~(1ULL << 63);
    KeUnstackDetachProcess(&apc);
    FlushTlb(scVa);
    {
        U64 chk = 0, pa = 0;
        KeStackAttachProcess(proc, &apc);
        if (PteLoad(scVa, &chk, &pa))
            KLogF("[sc3] pte after=0x%llX nx=%d\n", chk, (int)((chk >> 63) & 1));
        KeUnstackDetachProcess(&apc);
    }

    /* spray user apcs over waiters: delivery depends on the thread actually
       reaching an alertable wait, so re-scan and top up while we poll */
    tCount = GetWaitingThreads(j->Pid, tids, 16, FALSE);
    KLogF("[sc3] candidate threads=%lu\n", tCount);
    for (i = 0; i < tCount && i < 16; i++) { QueueUserApc(tids[i], scVa, ctx); seen[seenCount++] = tids[i]; }

    {
        ULONG k, execMs = 0, sprayMs = -1;
        U64 c = 0, m = 0;

        for (k = 0; k < 120; k++) {
            MemRead(proc, dataVa, &c, 8);
            MemRead(proc, dataVa + 8, &m, 8);
            if (c != 0 && (ULONG)m == MAGIC32 && !execMs) {
                U64 ret = 0;
                execMs = (k + 1) * 250;
                U64 err = 0;
                MemRead(proc, dataVa + 0x10, &ret, 8);
                MemRead(proc, dataVa + 0x18, &err, 8);
                KLogF("[sc3] shellcode executed after %lu ms cnt=%Iu llw_ret=0x%llX lasterr=%Iu\n",
                      execMs, c, ret, err);
            }

            if (j->Pic[0]) {
                UCHAR head[16];
                if (NT_SUCCESS(MemRead(proc, scVa, head, 16))) {
                    if (head[0] != picHead[0] || head[1] != picHead[1] ||
                        head[2] != picHead[2] || head[3] != picHead[3]) {
                        KLog("[sc3] pic page stolen (content changed), stop\n");
                        break;
                    }
                }
                if (c != 0 && (ULONG)m == MAGIC32 && !execMs) {
                    execMs = (k + 1) * 250;
                    KLogF("[sc3] pic executed after %lu ms cnt=%Iu\n", execMs, c);
                }
                if (FileExists(L"\\??\\C:\\Users\\Public\\pic-ok.txt")) {
                    done = TRUE;
                    KLogF("[sc3] pic output file appeared after %lu ms\n", (k + 1) * 250);
                    break;
                }
            } else if (j->Dll[0]) {
                U64 h = 0;
                MemRead(proc, dataVa + 0x10, &h, 8);
                if (h) {
                    done = TRUE;
                    KLogF("[sc3] LoadLibraryW ok hmod=0x%llX after %lu ms\n", h, (k + 1) * 250);
                    break;
                }
            } else if (execMs) {
                done = TRUE;
                break;
            }

            /* top up: queue to waiters we have not targeted yet */
            if (k > 0 && (k % 8) == 0) {
                ULONG n, t2[16], j2, k2;
                ULONG nw = GetWaitingThreads(j->Pid, t2, 16, FALSE);
                for (j2 = 0; j2 < nw; j2++) {
                    BOOLEAN have = FALSE;
                    for (k2 = 0; k2 < seenCount; k2++) if (seen[k2] == t2[j2]) { have = TRUE; break; }
                    if (!have && seenCount < 32) { QueueUserApc(t2[j2], scVa, ctx); seen[seenCount++] = t2[j2]; n = nw; }
                }
                if (nw) KLogF("[sc3] topup t=%lu ms waiters=%lu queued_total=%lu\n", (k + 1) * 250, nw, seenCount);
                sprayMs = (ULONG)k;
            }
            SleepMs(250);
        }
        if (!done) KLogF("[sc3] no exec/load in 30s (cnt=%Iu mag=0x%X)\n", c, (ULONG)m);
        if (sprayMs == (ULONG)-1) KLog("[sc3] topup never ran\n");
    }
    /* never restore after spraying: other apcs stay queued on non-alertable
       threads and would later execute whatever bytes we left behind (a zero
       page = invalid instructions). the shellcode is idempotent and harmless. */
    if (done) KLog("[sc3] shellcode + non-exec bit retained by design (apc safety)\n");
    else KLog("[sc3] NOT restored either: apc may still be pending\n");
    return done;
}


/* ---------------- deterministic trigger: inline hook + trampoline ----------------
   payload at slot:
      pushfq / push rax rcx rdx r8 r9 r10 r11 / sub rsp,0x28
      movabs r11, data
      cmp qword [r11],0 / jne skip          <- re-entry guard
      mov qword [r11],1
      inc qword [r11+8]                     <- counter, driver polls this
      mov qword [r11+0x10], magic
   skip:
      add rsp,0x28 / pop ... / popfq
      <original N bytes>                    <- N is instruction-boundary safe (computed offline)
      movabs r11, func+N / jmp r11
*/
static ULONG BuildHookPayload(UCHAR* sc, U64 dataVa, U64 funcNext, const UCHAR* orig, ULONG n,
                             U64 picVa, BOOLEAN hasPic)
{
    ULONG k = 0, jmpPatch;

    sc[k++] = 0x9C;
    sc[k++] = 0x50;
    sc[k++] = 0x51;
    sc[k++] = 0x52;
    sc[k++] = 0x41; sc[k++] = 0x50;
    sc[k++] = 0x41; sc[k++] = 0x51;
    sc[k++] = 0x41; sc[k++] = 0x52;
    sc[k++] = 0x41; sc[k++] = 0x53;
    sc[k++] = 0x48; sc[k++] = 0x83; sc[k++] = 0xEC; sc[k++] = 0x28;
    sc[k++] = 0x49; sc[k++] = 0xBB;
    *(U64*)(sc + k) = dataVa; k += 8;
    sc[k++] = 0x49; sc[k++] = 0x83; sc[k++] = 0x3B; sc[k++] = 0x00;
    sc[k++] = 0x75; jmpPatch = k; k++;
    sc[k++] = 0x49; sc[k++] = 0xC7; sc[k++] = 0x03;
    sc[k++] = 0x01; sc[k++] = 0x00; sc[k++] = 0x00; sc[k++] = 0x00;
    sc[k++] = 0x49; sc[k++] = 0xFF; sc[k++] = 0x43; sc[k++] = 0x08;
    sc[k++] = 0x49; sc[k++] = 0xC7; sc[k++] = 0x43; sc[k++] = 0x10;
    *(ULONG*)(sc + k) = MAGIC32; k += 4;
    if (hasPic) {
        sc[k++] = 0x48; sc[k++] = 0xB9;
        *(U64*)(sc + k) = dataVa; k += 8;            /* mov rcx, table      */
        sc[k++] = 0x48; sc[k++] = 0xB8;
        *(U64*)(sc + k) = picVa; k += 8;             /* mov rax, pic        */
        sc[k++] = 0xFF; sc[k++] = 0xD0;              /* call rax            */
    }
    sc[jmpPatch] = (UCHAR)(k - (jmpPatch + 1));
    sc[k++] = 0x48; sc[k++] = 0x83; sc[k++] = 0xC4; sc[k++] = 0x28;
    sc[k++] = 0x41; sc[k++] = 0x5B;
    sc[k++] = 0x41; sc[k++] = 0x5A;
    sc[k++] = 0x41; sc[k++] = 0x59;
    sc[k++] = 0x41; sc[k++] = 0x58;
    sc[k++] = 0x5A;
    sc[k++] = 0x59;
    sc[k++] = 0x58;
    sc[k++] = 0x9D;
    { ULONG i; for (i = 0; i < n; i++) sc[k++] = orig[i]; }
    sc[k++] = 0x49; sc[k++] = 0xBB;
    *(U64*)(sc + k) = funcNext; k += 8;
    sc[k++] = 0x41; sc[k++] = 0xFF; sc[k++] = 0xE3;
    return k;
}

/* pte rw -> write bytes into the target code page -> restore pte (unhook4 pattern) */
static BOOLEAN PatchTargetBytes(PEPROCESS proc, U64 va, const UCHAR* bytes, ULONG n)
{
    KAPC_STATE apc;
    U64 pteVal = 0, pteAddr = 0;
    BOOLEAN ok = FALSE;

    KeStackAttachProcess(proc, &apc);
    if (PteLoad(va, &pteVal, &pteAddr)) {
        *(U64*)(ULONG_PTR)pteAddr = pteVal | 2;
        __invlpg((PVOID)(ULONG_PTR)va);
        RtlCopyMemory((PVOID)(ULONG_PTR)va, bytes, n);
        *(U64*)(ULONG_PTR)pteAddr = pteVal;
        __invlpg((PVOID)(ULONG_PTR)va);
        ok = TRUE;
    }
    KeUnstackDetachProcess(&apc);
    if (ok) FlushTlb(va);
    return ok;
}

static BOOLEAN DoHook(PEPROCESS proc, JOB* j, SCAN* s)
{
    KAPC_STATE apc;
    SLOT* best = NULL;
    U64 modBase, va, scVa, dataVa, pteVal = 0, pteAddr = 0;
    UCHAR payload[512], stub[12], orig[32];
    ULONG i, plen, k;
    BOOLEAN hit = FALSE, hasPic = FALSE;
    U64 picVa = 0;

    for (i = 0; i < s->Total; i++)
        if (s->Slots[i].Verified && (!best || s->Slots[i].Score > best->Score)) best = &s->Slots[i];
    if (!best) { KLog("[sc3] hook: no verified slot\n"); return FALSE; }
    if (j->HookN < 12 || j->HookN > 24) { KLogF("[sc3] hook: bad n=%lu\n", j->HookN); return FALSE; }

    modBase = TargetModuleBase(proc, j->HookMod);
    if (!modBase) { KLogF("[sc3] hook: module missing %ws\n", j->HookMod); return FALSE; }
    va = modBase + j->HookRva;
    for (i = 0; i < j->HookN; i++) orig[i] = j->HookOrig[i];

    scVa = best->Va;
    dataVa = scVa + 0x400;
    picVa = scVa + 0x800;
    if (j->Pic[0]) {
        UCHAR* blob = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x2000, 'picS');
        UCHAR* tbl = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x400, 'tblS');
        ULONG blen = 0;

        if (!blob || !tbl) {
            if (blob) ExFreePoolWithTag(blob, 'picS');
            if (tbl) ExFreePoolWithTag(tbl, 'tblS');
            return FALSE;
        }
        {
            WCHAR full[300];
            NTSTATUS rst;
            RtlStringCchCopyW(full, RTL_NUMBER_OF(full), L"\\??\\");
            RtlStringCchCatW(full, RTL_NUMBER_OF(full), j->Pic);
            rst = ReadFileAll(full, blob, 0x2000, &blen);
            if (!NT_SUCCESS(rst) || blen < 16 || blen > 0x800) {
                KLogF("[sc3] hook: pic read failed st=0x%X len=%lu\n", rst, blen);
                ExFreePoolWithTag(blob, 'picS');
                ExFreePoolWithTag(tbl, 'tblS');
                return FALSE;
            }
        }
        RtlZeroMemory(tbl, 0x400);
        *(U64*)(tbl + 0x18) = TargetResolveExport(proc, L"kernel32.dll", "CreateFileA");
        *(U64*)(tbl + 0x20) = TargetResolveExport(proc, L"kernel32.dll", "WriteFile");
        *(U64*)(tbl + 0x28) = TargetResolveExport(proc, L"kernel32.dll", "CloseHandle");
        *(U64*)(tbl + 0x30) = TargetResolveExport(proc, L"kernel32.dll", "GetCurrentProcessId");
        {   UNICODE_STRING up; ANSI_STRING an;
            RtlInitUnicodeString(&up, L"C:\\Users\\Public\\pic-ok.txt");
            an.Buffer = (PCHAR)(tbl + 0x38); an.Length = 0; an.MaximumLength = 259;
            RtlUnicodeStringToAnsiString(&an, &up, FALSE);
        }
        if (!NT_SUCCESS(MemWrite(proc, dataVa, tbl, 0x400))) KLog("[sc3] hook: table write failed\n");
        if (!NT_SUCCESS(MemWrite(proc, picVa, blob, blen))) KLog("[sc3] hook: pic write failed\n");
        hasPic = TRUE;
        KLogF("[sc3] hook: pic=%lu bytes at 0x%llX table=0x%llX\n", blen, picVa, dataVa);
        ExFreePoolWithTag(blob, 'picS');
        ExFreePoolWithTag(tbl, 'tblS');
    }

    RtlZeroMemory(payload, sizeof(payload));
    plen = BuildHookPayload(payload, dataVa, va + j->HookN, orig, j->HookN, picVa, hasPic);
    if (!NT_SUCCESS(MemWrite(proc, scVa, payload, plen))) { KLog("[sc3] hook: payload write failed\n"); return FALSE; }
    if (!hasPic) { U64 z[3]; z[0] = 0; z[1] = 0; z[2] = 0; MemWrite(proc, dataVa, z, 24); }

    /* make the payload page executable */
    KeStackAttachProcess(proc, &apc);
    if (PteLoad(scVa, &pteVal, &pteAddr)) *(U64*)(ULONG_PTR)pteAddr = pteVal & ~(1ULL << 63);
    KeUnstackDetachProcess(&apc);
    FlushTlb(scVa);

    /* install: mov rax, payload ; jmp rax */
    stub[0] = 0x48; stub[1] = 0xB8;
    *(U64*)(stub + 2) = scVa;
    stub[10] = 0xFF; stub[11] = 0xE0;
    if (!PatchTargetBytes(proc, va, stub, 12)) {
        KLog("[sc3] hook: install failed (pte?)\n");
        return FALSE;
    }
    KLogF("[sc3] hook %ws+0x%X va=0x%llX payload=0x%llX n=%lu plen=%lu\n",
          j->HookMod, j->HookRva, va, scVa, j->HookN, plen);

    for (k = 0; k < 75; k++) {
        U64 c = 0, m = 0;
        SleepMs(200);
        MemRead(proc, dataVa + 8, &c, 8);
        MemRead(proc, dataVa + 0x10, &m, 8);
        if (c != 0 && (ULONG)m == MAGIC32) {
            hit = TRUE;
            KLogF("[sc3] hook HIT after %lu ms cnt=%Iu\n", (k + 1) * 200, c);
            break;
        }
        if (hasPic && FileExists(L"\\??\\C:\\Users\\Public\\pic-ok.txt") && k > 2) {
            hit = TRUE;
            KLogF("[sc3] pic output seen after %lu ms\n", (k + 1) * 200);
            break;
        }
    }

    /* restore immediately: a hook left in place runs every frame and is AC-visible */
    if (PatchTargetBytes(proc, va, orig, j->HookN)) KLog("[sc3] hook restored\n");
    else KLog("[sc3] hook RESTORE FAILED\n");
    return hit;
}


/* ---------------- window-proc trigger (process-local, no shared code page) ----------------
   page layout (one zero page):
      +0x000  payload blob  (OurWndProc at wndproc offset, Installer at wndinst offset)
      +0x400  API table
      +0x800  driver-built stub: WndProc entry -> reshuffles args -> OurWndProc(table, ...)
*/
#define TBL_COUNTER 0x00
#define TBL_MAGIC   0x08
#define TBL_PID     0x10
#define TBL_CF      0x18
#define TBL_WF      0x20
#define TBL_CH      0x28
#define TBL_GP      0x30
#define TBL_ENUM    0x38
#define TBL_GWTP    0x40
#define TBL_IWV     0x48
#define TBL_GWR     0x50
#define TBL_SWLP    0x58
#define TBL_GWLP    0x60
#define TBL_CWPW    0x68
#define TBL_WNDVA   0x70
#define TBL_TID     0x78
#define TBL_HWND    0x80
#define TBL_OLDPROC 0x88
#define TBL_BEST    0x90
#define TBL_HIT     0x98
#define TBL_PATH    0xA0
#define TBL_BEACON  0x1A8
#define TBL_FINDW   0x1B0
#define TBL_GLE     0x1B8
#define TBL_CLS     0x1C0

static VOID FillApiTable(PEPROCESS proc, UCHAR* tbl, U64 wndStubVa, PCWSTR outPath)
{
    RtlZeroMemory(tbl, 0x400);
    *(U64*)(tbl + TBL_CF)   = TargetResolveExport(proc, L"kernel32.dll", "CreateFileA");
    *(U64*)(tbl + TBL_WF)   = TargetResolveExport(proc, L"kernel32.dll", "WriteFile");
    *(U64*)(tbl + TBL_CH)   = TargetResolveExport(proc, L"kernel32.dll", "CloseHandle");
    *(U64*)(tbl + TBL_GP)   = TargetResolveExport(proc, L"kernel32.dll", "GetCurrentProcessId");
    *(U64*)(tbl + TBL_ENUM) = TargetResolveExport(proc, L"user32.dll", "EnumWindows");
    *(U64*)(tbl + TBL_GWTP) = TargetResolveExport(proc, L"user32.dll", "GetWindowThreadProcessId");
    *(U64*)(tbl + TBL_IWV)  = TargetResolveExport(proc, L"user32.dll", "IsWindowVisible");
    *(U64*)(tbl + TBL_GWR)  = TargetResolveExport(proc, L"user32.dll", "GetWindowRect");
    *(U64*)(tbl + TBL_SWLP) = TargetResolveExport(proc, L"user32.dll", "SetWindowLongPtrW");
    *(U64*)(tbl + TBL_GWLP) = TargetResolveExport(proc, L"user32.dll", "GetWindowLongPtrW");
    *(U64*)(tbl + TBL_CWPW) = TargetResolveExport(proc, L"user32.dll", "CallWindowProcW");
    *(U64*)(tbl + TBL_WNDVA) = wndStubVa;
    *(U64*)(tbl + TBL_FINDW) = TargetResolveExport(proc, L"user32.dll", "FindWindowW");
    *(U64*)(tbl + TBL_GLE)   = TargetResolveExport(proc, L"kernel32.dll", "GetLastError");
    KLogF("[sc3] api swlp=0x%llX enum=0x%llX gwtr=0x%llX gwr=0x%llX cwpw=0x%llX\n",
          *(U64*)(tbl + TBL_SWLP), *(U64*)(tbl + TBL_ENUM), *(U64*)(tbl + TBL_GWTP),
          *(U64*)(tbl + TBL_GWR), *(U64*)(tbl + TBL_CWPW));
    {
        UNICODE_STRING up; ANSI_STRING an;
        RtlInitUnicodeString(&up, outPath);
        an.Buffer = (PCHAR)(tbl + TBL_PATH);
        an.Length = 0;
        an.MaximumLength = 259;
        RtlUnicodeStringToAnsiString(&an, &up, FALSE);
    }
}

static ULONG BuildWndStub(UCHAR* sc, U64 tableVa, U64 wndVa)
{
    ULONG k = 0;
    sc[k++] = 0x48; sc[k++] = 0x83; sc[k++] = 0xEC; sc[k++] = 0x28;        /* sub rsp,0x28      */
    sc[k++] = 0x4C; sc[k++] = 0x89; sc[k++] = 0x4C; sc[k++] = 0x24; sc[k++] = 0x20;  /* [rsp+20]=lp */
    sc[k++] = 0x49; sc[k++] = 0x89; sc[k++] = 0xCB;                        /* mov r11,rcx (hwnd)*/
    sc[k++] = 0x4D; sc[k++] = 0x89; sc[k++] = 0xC1;                        /* mov r9,r8  (wp)   */
    sc[k++] = 0x49; sc[k++] = 0x89; sc[k++] = 0xD0;                        /* mov r8,rdx (msg)  */
    sc[k++] = 0x4C; sc[k++] = 0x89; sc[k++] = 0xDA;                        /* mov rdx,r11(hwnd) */
    sc[k++] = 0x48; sc[k++] = 0xB9;
    *(U64*)(sc + k) = tableVa; k += 8;                                     /* mov rcx,table     */
    sc[k++] = 0x48; sc[k++] = 0xB8;
    *(U64*)(sc + k) = wndVa; k += 8;                                       /* mov rax,wndproc   */
    sc[k++] = 0xFF; sc[k++] = 0xD0;                                        /* call rax          */
    sc[k++] = 0x48; sc[k++] = 0x83; sc[k++] = 0xC4; sc[k++] = 0x28;        /* add rsp,0x28      */
    sc[k++] = 0xC3;
    return k;
}

static BOOLEAN DoWnd(PEPROCESS proc, JOB* j, SCAN* s)
{
    KAPC_STATE apc;
    SLOT* best = NULL;
    U64 pageBase, codeVa, tblVa, stubVa, pteVal = 0, pteAddr = 0;
    UCHAR* blob;
    UCHAR* tbl;
    UCHAR stub[64];
    ULONG i, blen = 0, slen, tCount;
    ULONG tids[16];

    for (i = 0; i < s->Total; i++)
        if (s->Slots[i].Verified && (!best || s->Slots[i].Score > best->Score)) best = &s->Slots[i];
    if (!best) { KLog("[sc3] wnd: no verified slot\n"); return FALSE; }
    if (!j->WndInst) { KLog("[sc3] wnd: missing wndinst\n"); return FALSE; }

    blob = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x1000, 'wndS');
    tbl  = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x400, 'wndT');
    if (!blob || !tbl) {
        if (blob) ExFreePoolWithTag(blob, 'wndS');
        if (tbl) ExFreePoolWithTag(tbl, 'wndT');
        return FALSE;
    }
    {   WCHAR full[300]; NTSTATUS rst;
        RtlStringCchCopyW(full, RTL_NUMBER_OF(full), L"\\??\\");
        RtlStringCchCatW(full, RTL_NUMBER_OF(full), j->Wnd);
        rst = ReadFileAll(full, blob, 0x1000, &blen);
        if (!NT_SUCCESS(rst) || blen < 32 || blen > 0x500) {
            KLogF("[sc3] wnd: read failed st=0x%X len=%lu\n", rst, blen);
            ExFreePoolWithTag(blob, 'wndS');
            ExFreePoolWithTag(tbl, 'wndT');
            return FALSE;
        }
    }

    pageBase = best->Page;
    codeVa = pageBase;
    tblVa = pageBase + 0x500;
    stubVa = pageBase + 0xC00;

    FillApiTable(proc, tbl, stubVa, L"C:\\Users\\Public\\pic-ok.txt");
    slen = BuildWndStub(stub, tblVa, codeVa + j->WndProcOff);

    if (!NT_SUCCESS(MemWrite(proc, codeVa, blob, blen))) { KLog("[sc3] wnd: blob write failed\n"); goto out; }
    if (!NT_SUCCESS(MemWrite(proc, tblVa, tbl, 0x400))) { KLog("[sc3] wnd: table write failed\n"); goto out; }
    if (!NT_SUCCESS(MemWrite(proc, stubVa, stub, slen))) { KLog("[sc3] wnd: stub write failed\n"); goto out; }

    KeStackAttachProcess(proc, &apc);
    if (PteLoad(pageBase, &pteVal, &pteAddr)) *(U64*)(ULONG_PTR)pteAddr = pteVal & ~(1ULL << 63);
    KeUnstackDetachProcess(&apc);
    FlushTlb(pageBase);
    KLogF("[sc3] wnd page=0x%llX blob=%lu stub=%lu inst=0x%llX wndproc=0x%llX table=0x%llX\n",
          pageBase, blen, slen, codeVa + j->WndInst, codeVa + j->WndProcOff, tblVa);

    /* stage 1: installer, retried because the window may not exist yet */
    {
        ULONG round;
        U64 tid = 0, hw = 0;

        for (round = 0; round < 40 && (!tid || !hw); round++) {
            ULONG k;
            WCHAR clsBuf[64];

            RtlZeroMemory(clsBuf, sizeof(clsBuf));
            if (j->WndClassCount)
                RtlStringCchCopyW(clsBuf, RTL_NUMBER_OF(clsBuf), j->WndClass[round % j->WndClassCount]);
            MemWrite(proc, tblVa + TBL_CLS, clsBuf, sizeof(clsBuf));
            KLogF("[sc3] wnd round %lu class=%ws\n", round, clsBuf);

            tCount = GetWaitingThreads(j->Pid, tids, 8, FALSE);
            for (i = 0; i < tCount && i < 6; i++) QueueUserApc(tids[i], codeVa + j->WndInst, tblVa);
            for (k = 0; k < 6; k++) {
                SleepMs(500);
                MemRead(proc, tblVa + TBL_TID, &tid, 8);
                MemRead(proc, tblVa + TBL_HWND, &hw, 8);
                if (tid && hw) break;
            }
        }
        if (!tid || !hw) {
            KLogF("[sc3] wnd: window not found (tid=%Iu hwnd=0x%llX)\n", tid, hw);
            goto out;
        }
        KLogF("[sc3] wnd: hwnd=0x%llX ui_tid=%Iu -> swap apc\n", hw, tid);
        if (!QueueUserApc((ULONG)tid, codeVa + j->WndSwap, tblVa)) {
            KLog("[sc3] wnd: swap apc failed\n");
            goto out;
        }
    }

    {
        ULONG k;
        U64 cnt = 0, mag = 0, hit = 0;
        for (k = 0; k < 80; k++) {
            SleepMs(200);
            MemRead(proc, tblVa + TBL_COUNTER, &cnt, 8);
            MemRead(proc, tblVa + TBL_MAGIC, &mag, 8);
            MemRead(proc, tblVa + TBL_HIT, &hit, 8);
            if ((k % 10) == 0) {
                U64 hw = 0, op = 0, ba = 0;
                MemRead(proc, tblVa + TBL_HWND, &hw, 8);
                MemRead(proc, tblVa + TBL_OLDPROC, &op, 8);
                MemRead(proc, tblVa + TBL_BEST, &ba, 8);
                { U64 bc = 0;
                  MemRead(proc, tblVa + 0x1A8, &bc, 8);
                  KLogF("[sc3] wnd poll t=%lu cnt=%Iu mag=0x%X hit=%Iu hwnd=0x%llX old=0x%llX area=%llu beacon=0x%llX\n",
                        (k + 1) * 200, cnt, (ULONG)mag, hit, hw, op, ba, bc); }
            }
            if (hit) {
                KLogF("[sc3] WNDPROC HIT after %lu ms\n", (k + 1) * 200);
                goto out;
            }
        }
        KLog("[sc3] wnd: no installer run / no message\n");
    }

out:
    ExFreePoolWithTag(blob, 'wndS');
    ExFreePoolWithTag(tbl, 'wndT');
    return FALSE;
}


/* ---------------- IAT hook: kernel-side install, no APC needed ---------------- */
static U64 IatFindSlot(PEPROCESS proc, PCWSTR modName, PCWSTR dllWanted, PCWSTR apiWanted, U64* outOld)
{
    KAPC_STATE apc;
    U64 base, nt, impRva, desc;
    U64 slot = 0;
    ANSI_STRING apiA, dllA;
    CHAR apiB[128], dllB[128];
    UNICODE_STRING u;

    if (RtlUnicodeStringToAnsiString(&apiA, (PUNICODE_STRING)&(UNICODE_STRING){0}, TRUE) == 0) { /* noop */ }
    RtlInitUnicodeString(&u, apiWanted);
    apiA.Buffer = apiB; apiA.Length = 0; apiA.MaximumLength = sizeof(apiB);
    if (!NT_SUCCESS(RtlUnicodeStringToAnsiString(&apiA, &u, FALSE))) return 0;
    RtlInitUnicodeString(&u, dllWanted);
    dllA.Buffer = dllB; dllA.Length = 0; dllA.MaximumLength = sizeof(dllB);
    if (!NT_SUCCESS(RtlUnicodeStringToAnsiString(&dllA, &u, FALSE))) return 0;

    KeStackAttachProcess(proc, &apc);
    base = TargetModuleBase(proc, modName);
    if (base) {
        nt = base + *(ULONG*)(ULONG_PTR)(base + 0x3C);
        impRva = *(ULONG*)(ULONG_PTR)(nt + 0x88 + 8);        /* DataDirectory[1].VirtualAddress */
        KLogF("[sc3] iat base=0x%llX nt=0x%llX impRva=0x%X\n", base, nt, impRva);
        if (impRva) {
            for (desc = base + impRva; ; desc += 20) {
                ULONG oft = *(ULONG*)(ULONG_PTR)(desc + 0);
                ULONG nameRva = *(ULONG*)(ULONG_PTR)(desc + 12);
                ULONG ft = *(ULONG*)(ULONG_PTR)(desc + 16);
                PCSTR dllName;
                BOOLEAN dllOk;
                ULONG i;

                if (!nameRva || !ft) break;
                dllName = (PCSTR)(ULONG_PTR)(base + nameRva);
                KLogF("[sc3] iat desc dll=%s oft=0x%X ft=0x%X\n", dllName, oft, ft);
                dllOk = TRUE;
                if (dllB[0]) {
                    ULONG k = 0;
                    while (dllName[k] && dllB[k]) {
                        CHAR a = dllName[k], b = dllB[k];
                        if (a >= 'a' && a <= 'z') a -= 32;
                        if (b >= 'a' && b <= 'z') b -= 32;
                        if (a != b) { dllOk = FALSE; break; }
                        k++;
                    }
                    if (dllOk && (dllName[k] || dllB[k])) dllOk = FALSE;
                }
                if (!dllOk) continue;
                if (!oft) continue;
                for (i = 0; i < 4096; i++) {
                    U64 ent = *(U64*)(ULONG_PTR)(base + oft + i * 8);
                    PCSTR nm;
                    ULONG k;
                    if (!ent) break;
                    if (ent & 0x8000000000000000ull) continue;   /* ordinal */
                    nm = (PCSTR)(ULONG_PTR)(base + (ULONG)(ent & 0x7FFFFFFF) + 2);   /* skip hint */
                    if (i < 4) KLogF("[sc3] iat thunk[%lu]=%s want=%s\n", i, nm, apiB);
                    for (k = 0; nm[k] && apiB[k] && nm[k] == apiB[k]; k++) { }
                    if (nm[k] == 0 && apiB[k] == 0) {
                        slot = base + ft + i * 8;
                        break;
                    }
                }
                if (slot) break;
            }
        }
    }
    KeUnstackDetachProcess(&apc);
    if (slot) {
        U64 v = 0;
        if (NT_SUCCESS(MemRead(proc, slot, &v, 8))) *outOld = v;
        else { slot = 0; }
    }
    return slot;
}

/* QPC detour: forward the call, then run our tick only if >= threshold
   ticks (= ~16ms) have passed since the last one.  All state lives in the
   table, so nothing is touched in shared memory.
      table+0x18 = original QueryPerformanceCounter
      table+0x20 = last accepted timestamp
      table+0x28 = threshold (ticks)
      table+0x08 = accepted tick count       table+0x30 = raw call count
*/
/* v2: baseline + push/pop rcx (verify the save/restore path alone) */
/* v4: table pointer lives in rbx (callee-preserved), out pointer in rbx too,
   rax (the API return value) is never touched; time gate = 16ms */
/* v3: baseline + out pointer kept in rbx (no gate, no raw counter) */
/* v3 (proven in apex: 13669 calls / 200ms) -- forward + beat, nothing else.
   throttling/frame logic lives in the driver, not here.
     table+0x18 original QPC   table+0x08 beat counter   table+0x10 magic
*/
static ULONG BuildIatPayload(UCHAR* sc, U64 tableVa)
{
    ULONG k = 0;
    sc[k++] = 0x49; sc[k++] = 0xBB;
    *(U64*)(sc + k) = tableVa; k += 8;                     /* movabs r11, table */
    sc[k++] = 0x48; sc[k++] = 0x83; sc[k++] = 0xEC; sc[k++] = 0x28;
    sc[k++] = 0x49; sc[k++] = 0xFF; sc[k++] = 0x53; sc[k++] = 0x18;   /* call [r11+0x18] */
    sc[k++] = 0x48; sc[k++] = 0x83; sc[k++] = 0xC4; sc[k++] = 0x28;
    sc[k++] = 0x49; sc[k++] = 0xBB;
    *(U64*)(sc + k) = tableVa; k += 8;
    sc[k++] = 0x49; sc[k++] = 0xFF; sc[k++] = 0x43; sc[k++] = 0x08;   /* inc [r11+8] */
    sc[k++] = 0x49; sc[k++] = 0xC7; sc[k++] = 0x43; sc[k++] = 0x10;
    *(ULONG*)(sc + k) = MAGIC32; k += 4;
    sc[k++] = 0xC3;
    return k;
}
static BOOLEAN DoIat(PEPROCESS proc, JOB* j, SCAN* s)
{
    KAPC_STATE apc;
    SLOT* best = NULL;
    U64 pageBase, tblVa, slotVa = 0, oldVal = 0, newVal, pteVal = 0, pteAddr = 0;
    UCHAR payload[64];
    ULONG i, plen, k;
    BOOLEAN hit = FALSE;

    for (i = 0; i < s->Total; i++)
        if (s->Slots[i].Verified && (!best || s->Slots[i].Score > best->Score)) best = &s->Slots[i];
    if (!best) { KLog("[sc3] iat: no slot\n"); return FALSE; }
    if (!j->IatApi[0]) { KLog("[sc3] iat: no api\n"); return FALSE; }

    slotVa = IatFindSlot(proc, j->IatMod[0] ? j->IatMod : j->Name, j->IatDll, j->IatApi, &oldVal);
    if (!slotVa) { KLogF("[sc3] iat: slot not found %ws!%ws\n", j->IatDll, j->IatApi); return FALSE; }
    KLogF("[sc3] iat slot=0x%llX old=0x%llX\n", slotVa, oldVal);

    pageBase = best->Page;
    tblVa = pageBase + 0x500;
    plen = BuildIatPayload(payload, tblVa);

    if (!NT_SUCCESS(MemWrite(proc, pageBase, payload, plen))) { KLog("[sc3] iat: payload write failed\n"); return FALSE; }
    { U64 t[4]; t[0] = 0; t[1] = 0; t[2] = 0; t[3] = oldVal;   /* 0x18 = original QPC */
      MemWrite(proc, tblVa, t, sizeof(t)); }

    KeStackAttachProcess(proc, &apc);
    if (PteLoad(pageBase, &pteVal, &pteAddr)) *(U64*)(ULONG_PTR)pteAddr = pteVal & ~(1ULL << 63);
    KeUnstackDetachProcess(&apc);
    FlushTlb(pageBase);

    newVal = pageBase;
    if (!PatchTargetBytes(proc, slotVa, (const UCHAR*)&newVal, 8)) {
        KLog("[sc3] iat: patch slot failed\n");
        return FALSE;
    }
    KLogF("[sc3] iat hooked -> 0x%llX\n", pageBase);

    /* driver-side throttling: 16ms windows over the beat counter.
       the stub stays "forward + inc" only -- no gate, no register tricks. */
    {
        ULONG w, frames = 0;
        U64 prev = 0;

        for (w = 1; w <= 6; w++) {
            ULONG k;
            for (k = 0; k < 25; k++) {
                U64 cur = 0;
                UCHAR head[4];

                MemRead(proc, tblVa + 0x08, &cur, 8);
                if (cur != prev) { frames++; prev = cur; }
                MemRead(proc, pageBase, head, 4);
                if (head[0] != payload[0] || head[1] != payload[1]) {
                    KLog("[sc3] iat: payload page changed, stop\n");
                    w = 99;
                    break;
                }
                SleepMs(16);
            }
            if (w == 99) break;
            KLogF("[sc3] frame window %lu: %lu beats/400ms total=%lu\n", w, frames, prev);
            frames = 0;
        }
        hit = (prev != 0);
        KLogF("[sc3] throttle summary: beats=%lu ok=%d\n", prev, (int)hit);
    }

    {
        ULONG r;
        BOOLEAN ok = FALSE;
        for (r = 0; r < 5 && !ok; r++) {
            ok = PatchTargetBytes(proc, slotVa, (const UCHAR*)&oldVal, 8);
            if (!ok) { KLogF("[sc3] iat: restore retry %lu\n", r + 1); SleepMs(50); }
        }
        KLog(ok ? "[sc3] iat restored\n" : "[sc3] iat: RESTORE FAILED\n");
    }
    return hit;
}

/* read-only: list every import of the target module (dxgi/d3d11 symbol survey) */
static VOID DumpImports(PEPROCESS proc, PCWSTR modName)
{
    KAPC_STATE apc;
    U64 base, nt, impRva, desc;
    ULONG total = 0;

    KeStackAttachProcess(proc, &apc);
    base = TargetModuleBase(proc, modName);
    KLogF("[sc3] impdump base=0x%llX\n", base);
    if (base) {
        nt = base + *(ULONG*)(ULONG_PTR)(base + 0x3C);
        impRva = *(ULONG*)(ULONG_PTR)(nt + 0x90);
        KLogF("[sc3] impdump dirRva=0x%X\n", impRva);
        if (impRva) {
            for (desc = base + impRva; ; desc += 20) {
                ULONG oft = *(ULONG*)(ULONG_PTR)(desc + 0);
                ULONG nameRva = *(ULONG*)(ULONG_PTR)(desc + 12);
                ULONG ft = *(ULONG*)(ULONG_PTR)(desc + 16);
                PCSTR dll;
                ULONG i;

                if (!nameRva || !ft) break;
                dll = (PCSTR)(ULONG_PTR)(base + nameRva);
                KLogF("[sc3] impdump --- %s\n", dll);
                if (!oft) continue;
                for (i = 0; i < 512; i++) {
                    U64 ent = *(U64*)(ULONG_PTR)(base + oft + i * 8);
                    if (!ent) break;
                    if (ent & 0x8000000000000000ull) {
                        KLogF("[sc3] impdump   #%lu\n", (ULONG)(ent & 0xFFFF));
                    } else {
                        PCSTR nm = (PCSTR)(ULONG_PTR)(base + (ULONG)(ent & 0x7FFFFFFF) + 2);
                        KLogF("[sc3] impdump   %s\n", nm);
                    }
                    total++;
                }
            }
        }
    }
    KeUnstackDetachProcess(&apc);
    KLogF("[sc3] impdump total=%lu\n", total);
}

/* read-only: find COM objects whose vtable lives inside a given module.
   for a DX12 swapchain the object's first qword points at its vtable, and
   vtable[3] (Release) and vtable[8] (Present) both live in dxgi. */
static VOID ScanVtable(PEPROCESS proc, PCWSTR modName)
{
    REG* regs;
    UCHAR* buf;
    ULONG regCount, i, found = 0;
    U64 modBase, modSize = 0;

    modBase = TargetModuleBase(proc, modName);
    if (modBase) {
        KAPC_STATE apc;
        U64 nt;
        KeStackAttachProcess(proc, &apc);
        nt = modBase + *(ULONG*)(ULONG_PTR)(modBase + 0x3C);
        modSize = *(ULONG*)(ULONG_PTR)(nt + 0x50);      /* SizeOfImage */
        KeUnstackDetachProcess(&apc);
    }
    KLogF("[sc3] vtscan mod=%ws base=0x%llX size=0x%llX\n", modName, modBase, modSize);
    if (!modBase || !modSize) return;

    regs = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(REG) * MAX_REG, 'regS');
    buf  = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'vtbS');
    if (!regs || !buf) { if (regs) ExFreePoolWithTag(regs,'regS'); if (buf) ExFreePoolWithTag(buf,'vtbS'); return; }

    regCount = EnumRW(proc, regs, MAX_REG, 1500);   /* RW private, >=0x8000 */
    KLogF("[sc3] vtscan regions=%lu\n", regCount);

    for (i = 0; i < regCount && found < 24; i++) {
        U64 off;
        for (off = 0; off + 0x10000 <= regs[i].Size && found < 24; off += 0x10000) {
            SIZE_T done = 0;
            ULONG k;
            RtlZeroMemory(buf, 0x10000);
            MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(regs[i].Base + off),
                                PsGetCurrentProcess(), buf, 0x10000, KernelMode, &done);
            if (done < 0x1000) continue;
            for (k = 0; k + 8 <= 0x10000; k += 8) {
                U64 v = *(U64*)(buf + k);
                U64 slot3, slot8;
                if (v < modBase || v >= modBase + modSize) continue;
                if (v & 7) continue;
                if (!NT_SUCCESS(MemRead(proc, v + 16, &slot3, 8))) continue;   /* Release   */
                if (!NT_SUCCESS(MemRead(proc, v + 64, &slot8, 8))) continue;   /* Present   */
                if (slot3 < modBase || slot3 >= modBase + modSize) continue;
                if (slot8 < modBase || slot8 >= modBase + modSize) continue;
                if (slot3 == slot8) continue;
                KLogF("[sc3] vtscan obj=0x%llX (field at 0x%llX) vtable=0x%llX rel3=0x%llX rel8=0x%llX\n",
                      regs[i].Base + off + k, regs[i].Base + off + k, v,
                      slot3 - modBase, slot8 - modBase);
                found++;
                if (found >= 24) break;
            }
        }
    }
    KLogF("[sc3] vtscan found=%lu\n", found);
    ExFreePoolWithTag(regs, 'regS');
    ExFreePoolWithTag(buf, 'vtbS');
}

/* ---------------- swapchain hunt: repoint one candidate at a time ----------------
   stub (tail call, nothing but r11 clobbered):
       mov r11, table ; lock inc [r11+0x18] ; mov rax,[r11+0x08] ; jmp rax
   table+0x08 = original Present, table+0x18 = hit counter
   only the object's first qword is written, and it is restored immediately.
*/
static ULONG BuildForwardStub(UCHAR* sc, U64 tableVa)
{
    ULONG k = 0;
    sc[k++] = 0x49; sc[k++] = 0xBB;
    *(U64*)(sc + k) = tableVa; k += 8;                       /* movabs r11, table */
    sc[k++] = 0xF0; sc[k++] = 0x49; sc[k++] = 0xFF; sc[k++] = 0x43; sc[k++] = 0x18;  /* lock inc [r11+18] */
    sc[k++] = 0x49; sc[k++] = 0x8B; sc[k++] = 0x43; sc[k++] = 0x08;                 /* mov rax,[r11+8] */
    sc[k++] = 0xFF; sc[k++] = 0xE0;                          /* jmp rax           */
    return k;
}

static BOOLEAN DoVtTrial(PEPROCESS proc, JOB* j, SCAN* s)
{
    SLOT* best = NULL;
    U64 pageBase, tblVa, copyVa, stubVa, pteVal = 0, pteAddr = 0;
    UCHAR stub[32], vtc[0x100];
    ULONG i, slen;
    ULONG tried = 0;
    BOOLEAN hit = FALSE;

    for (i = 0; i < s->Total; i++)
        if (s->Slots[i].Verified && (!best || s->Slots[i].Score > best->Score)) best = &s->Slots[i];
    if (!best) { KLog("[sc3] vt: no slot\n"); return FALSE; }

    pageBase = best->Page;
    tblVa  = pageBase + 0x400;
    copyVa = pageBase + 0x600;
    stubVa = pageBase + 0x800;

    RtlZeroMemory(stub, sizeof(stub));
    slen = BuildForwardStub(stub, tblVa);
    MemWrite(proc, stubVa, stub, slen);

    /* clear NX on the page so the stub is executable */
    {
        KAPC_STATE apc;
        KeStackAttachProcess(proc, &apc);
        if (PteLoad(pageBase, &pteVal, &pteAddr)) *(U64*)(ULONG_PTR)pteAddr = pteVal & ~(1ULL << 63);
        KeUnstackDetachProcess(&apc);
        FlushTlb(pageBase);
    }

    /* walk the same candidate set the scanner logs, one object at a time */
    {
        REG* regs = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(REG) * MAX_REG, 'regS');
        UCHAR* buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'vtbS');
        U64 modBase, modSize = 0;
        ULONG regCount;

        if (!regs || !buf) {
            if (regs) ExFreePoolWithTag(regs, 'regS');
            if (buf) ExFreePoolWithTag(buf, 'vtbS');
            return FALSE;
        }
        modBase = TargetModuleBase(proc, j->VtMod[0] ? j->VtMod : L"dxgi.dll");
        if (modBase) {
            KAPC_STATE apc; U64 nt;
            KeStackAttachProcess(proc, &apc);
            nt = modBase + *(ULONG*)(ULONG_PTR)(modBase + 0x3C);
            modSize = *(ULONG*)(ULONG_PTR)(nt + 0x50);
            KeUnstackDetachProcess(&apc);
        }
        if (!modBase || !modSize) { ExFreePoolWithTag(regs,'regS'); ExFreePoolWithTag(buf,'vtbS'); return FALSE; }

        regCount = EnumRW(proc, regs, MAX_REG, 1500);
        for (i = 0; i < regCount && !hit && tried < 24; i++) {
            U64 off;
            for (off = 0; off + 0x10000 <= regs[i].Size && !hit && tried < 24; off += 0x10000) {
                SIZE_T done = 0;
                ULONG k;
                RtlZeroMemory(buf, 0x10000);
                MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(regs[i].Base + off), PsGetCurrentProcess(),
                                    buf, 0x10000, KernelMode, &done);
                if (done < 0x1000) continue;
                for (k = 0; k + 8 <= done; k += 8) {
                    U64 v = *(U64*)(buf + k);
                    U64 slot2, slot8, orig;
                    U64 objVa;
                    ULONG w;

                    if (v < modBase || v >= modBase + modSize || (v & 7)) continue;
                    if (!NT_SUCCESS(MemRead(proc, v + 16, &slot2, 8))) continue;
                    if (!NT_SUCCESS(MemRead(proc, v + 64, &slot8, 8))) continue;
                    if (slot2 < modBase || slot2 >= modBase + modSize) continue;
                    if (slot8 < modBase || slot8 >= modBase + modSize) continue;
                    if (slot2 == slot8) continue;

                    objVa = regs[i].Base + off + k;
                    tried++;
                    {   /* copy the vtable, patch Present, repoint the object */
                        UCHAR vt[0x100];
                        U64 o[3] = { 0, slot8, 0 };         /* table: [+8]=orig Present */
                        if (!NT_SUCCESS(MemRead(proc, v, vt, sizeof(vt)))) continue;
                        { ULONG sl = j->VtSlot ? j->VtSlot : 22;
                          if (!NT_SUCCESS(MemRead(proc, v + sl * 8, &slot8, 8))) continue;
                          *(U64*)(vt + sl * 8) = stubVa; }
                        if (!NT_SUCCESS(MemWrite(proc, copyVa, vt, sizeof(vt)))) continue;
                        if (!NT_SUCCESS(MemWrite(proc, tblVa, o, sizeof(o)))) continue;
                        orig = v;
                        if (!NT_SUCCESS(MemWrite(proc, objVa, &copyVa, 8))) continue;
                        {   U64 rb0 = 0, rb8 = 0;
                            MemRead(proc, objVa, &rb0, 8);
                            MemRead(proc, copyVa + (j->VtSlot ? j->VtSlot : 22) * 8, &rb8, 8);
                            KLogF("[sc3] vt readback obj0=0x%llX want=0x%llX copyslot=0x%llX want=0x%llX\n",
                                  rb0, copyVa, rb8, stubVa);
                        }
                    }

                    {   /* measure rate over 2s */
                        U64 prev = 0, c1, c2;
                        MemRead(proc, tblVa + 0x18, &c1, 8);
                        SleepMs(1000);
                        MemRead(proc, tblVa + 0x18, &c2, 8);
                        prev = c2 - c1;
                        KLogF("[sc3] vt trial obj=0x%llX vtable=0x%llX rel8=0x%llX rate=%Iu/s\n",
                              objVa, v, slot8 - modBase, prev);
                        if (prev >= 30 && prev <= 400) {
                            hit = TRUE;
                            KLogF("[sc3] vt MATCH obj=0x%llX vtable=0x%llX present_rel=0x%llX\n",
                                  objVa, v, slot8 - modBase);
                        }
                    }

                    /* restore the object's vtable pointer */
                    if (!NT_SUCCESS(MemWrite(proc, objVa, &orig, 8)))
                        KLogF("[sc3] vt: restore FAILED obj=0x%llX\n", objVa);
                    (void)w;
                }
            }
        }
        KLogF("[sc3] vt trial done tried=%lu hit=%d\n", tried, (int)hit);
        ExFreePoolWithTag(regs, 'regS');
        ExFreePoolWithTag(buf, 'vtbS');
    }
    return hit;
}

/* ---------------- QI identification: ask each validated candidate ----------------
   stub (per frame, one shot):
       push rbx / mov rbx,rcx / movabs r11,table
       cmp qword [r11],0 / jne fwd
       mov qword [r11],1 / mov rcx,r11 / movabs rax,QInit / sub rsp,0x20 / call rax / add rsp,0x20
     fwd:
       mov rcx,rbx / pop rbx / movabs r11,table / mov rax,[r11+8] / jmp rax
   table: +0x00 stage +0x08 origQpc +0x10 count +0x18 iid[2] +0x28 hitObj
          +0x30 hitVt +0x38 hitOk +0x40 cand[40]
*/
static ULONG BuildQiStub(UCHAR* sc, U64 tableVa, U64 initVa)
{
    ULONG k = 0, jneAt;

    sc[k++] = 0x53;                                     /* push rbx          */
    sc[k++] = 0x48; sc[k++] = 0x89; sc[k++] = 0xCB;     /* mov rbx, rcx      */
    sc[k++] = 0x49; sc[k++] = 0xBB;
    *(U64*)(sc + k) = tableVa; k += 8;
    sc[k++] = 0x49; sc[k++] = 0x83; sc[k++] = 0x3B; sc[k++] = 0x00;   /* cmp [r11],0 */
    sc[k++] = 0x75; jneAt = k; k++;
    sc[k++] = 0x49; sc[k++] = 0xC7; sc[k++] = 0x03;
    sc[k++] = 0x01; sc[k++] = 0x00; sc[k++] = 0x00; sc[k++] = 0x00;   /* mov [r11],1 */
    sc[k++] = 0x4C; sc[k++] = 0x89; sc[k++] = 0xD9;                   /* mov rcx,r11 */
    sc[k++] = 0x48; sc[k++] = 0xB8;
    *(U64*)(sc + k) = initVa; k += 8;
    sc[k++] = 0x48; sc[k++] = 0x83; sc[k++] = 0xEC; sc[k++] = 0x20;
    sc[k++] = 0xFF; sc[k++] = 0xD0;
    sc[k++] = 0x48; sc[k++] = 0x83; sc[k++] = 0xC4; sc[k++] = 0x20;
    sc[jneAt] = (UCHAR)(k - (jneAt + 1));
    sc[k++] = 0x48; sc[k++] = 0x89; sc[k++] = 0xD9;                   /* mov rcx, rbx */
    sc[k++] = 0x5B;                                                   /* pop rbx      */
    sc[k++] = 0x49; sc[k++] = 0xBB;
    *(U64*)(sc + k) = tableVa; k += 8;
    sc[k++] = 0x49; sc[k++] = 0x8B; sc[k++] = 0x43; sc[k++] = 0x08;   /* mov rax,[r11+8] */
    sc[k++] = 0xFF; sc[k++] = 0xE0;                                   /* jmp rax      */
    return k;
}

static ULONG BuildFwdStub2(UCHAR* sc, U64 tableVa)
{
    ULONG k = 0;
    sc[k++] = 0x49; sc[k++] = 0xBB;
    *(U64*)(sc + k) = tableVa; k += 8;
    sc[k++] = 0xF0; sc[k++] = 0x49; sc[k++] = 0xFF; sc[k++] = 0x83;
    *(ULONG*)(sc + k) = 0x210; k += 4;                  /* lock inc [r11+0x210] */
    sc[k++] = 0x49; sc[k++] = 0x8B; sc[k++] = 0x83;
    *(ULONG*)(sc + k) = 0x208; k += 4;                  /* mov rax,[r11+0x208]  */
    sc[k++] = 0xFF; sc[k++] = 0xE0;
    return k;
}

/* scan RW memory for a given qword value (find a cached function pointer slot) */
static ULONG ScanForValue(PEPROCESS proc, U64 target, PCSTR label, ULONG maxHits)
{
    REG* regs;
    UCHAR* buf;
    ULONG regCount, i, hits = 0;

    regs = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(REG) * MAX_REG, 'regS');
    buf  = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'vtbS');
    if (!regs || !buf) { if (regs) ExFreePoolWithTag(regs,'regS'); if (buf) ExFreePoolWithTag(buf,'vtbS'); return 0; }

    regCount = EnumRW(proc, regs, MAX_REG, 1500);
    for (i = 0; i < regCount && hits < maxHits; i++) {
        U64 off;
        for (off = 0; off + 0x10000 <= regs[i].Size && hits < maxHits; off += 0x10000) {
            SIZE_T done = 0; ULONG k;
            RtlZeroMemory(buf, 0x10000);
            MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(regs[i].Base + off), PsGetCurrentProcess(),
                                buf, 0x10000, KernelMode, &done);
            if (done < 0x1000) continue;
            for (k = 0; k + 8 <= done && hits < maxHits; k += 8) {
                if (*(U64*)(buf + k) == target) {
                    U64 hitVa = regs[i].Base + off + k;
                    if (hitVa >= g_skipLo && hitVa < g_skipHi) continue;   /* our own page */
                    KLogF("[sc3] cache[%s] hit at 0x%llX\n", label, hitVa);
                    hits++;
                }
            }
        }
    }
    KLogF("[sc3] cache[%s] target=0x%llX hits=%lu\n", label, target, hits);
    ExFreePoolWithTag(regs, 'regS');
    ExFreePoolWithTag(buf, 'vtbS');
    return hits;
}

static BOOLEAN DoQiTest(PEPROCESS proc, JOB* j, SCAN* s)
{
    SLOT* best = NULL;
    U64 pageBase, tblVa, stubVa, initVa, slotVa = 0, oldVal = 0, pteVal = 0, pteAddr = 0;
    U64 modBase, modSize = 0, cand[40];
    UCHAR stub[128];
    UCHAR* pay;
    UCHAR* tbl;
    ULONG i, slen, payLen = 0, nCand = 0, k;
    BOOLEAN hit = FALSE;

    for (i = 0; i < s->Total; i++)
        if (s->Slots[i].Verified && (!best || s->Slots[i].Score > best->Score)) best = &s->Slots[i];
    if (!best) { KLog("[sc3] qi: no zero page\n"); return FALSE; }
    if (!j->QiPayload[0]) { KLog("[sc3] qi: no payload\n"); return FALSE; }

    pageBase = best->Page;
    g_skipLo = pageBase;
    g_skipHi = pageBase + 0x1000;
    stubVa = pageBase;              /* stub at page start */
    tblVa  = pageBase + 0x400;
    initVa = pageBase + 0x800;

    pay = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x400, 'qiPS');
    tbl = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x400, 'qiTS');
    if (!pay || !tbl) { if (pay) ExFreePoolWithTag(pay,'qiPS'); if (tbl) ExFreePoolWithTag(tbl,'qiTS'); return FALSE; }

    {   WCHAR full[300]; NTSTATUS rst;
        RtlStringCchCopyW(full, RTL_NUMBER_OF(full), L"\\??\\");
        RtlStringCchCatW(full, RTL_NUMBER_OF(full), j->QiPayload);
        rst = ReadFileAll(full, pay, 0x400, &payLen);
        if (!NT_SUCCESS(rst) || payLen < 16 || payLen > 0x400) {
            KLogF("[sc3] qi: payload read failed st=0x%X len=%lu\n", rst, payLen);
            ExFreePoolWithTag(pay, 'qiPS'); ExFreePoolWithTag(tbl, 'qiTS');
            return FALSE;
        }
    }

    modBase = TargetModuleBase(proc, j->VtMod[0] ? j->VtMod : L"dxgi.dll");
    if (modBase) {
        KAPC_STATE apc; U64 nt;
        KeStackAttachProcess(proc, &apc);
        nt = modBase + *(ULONG*)(ULONG_PTR)(modBase + 0x3C);
        modSize = *(ULONG*)(ULONG_PTR)(nt + 0x50);
        KeUnstackDetachProcess(&apc);
    }
    if (!modBase || !modSize) { ExFreePoolWithTag(pay,'qiPS'); ExFreePoolWithTag(tbl,'qiTS'); return FALSE; }

    slotVa = IatFindSlot(proc, j->IatMod[0] ? j->IatMod : j->Name, j->IatDll, j->IatApi, &oldVal);
    if (!slotVa) { KLog("[sc3] qi: qpc slot not found\n"); ExFreePoolWithTag(pay,'qiPS'); ExFreePoolWithTag(tbl,'qiTS'); return FALSE; }

    /* collect candidates with the three validations, all done here (safe reads) */
    {
        REG* regs = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(REG) * MAX_REG, 'regS');
        UCHAR* buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'vtbS');
        ULONG regCount;
        if (regs && buf) {
            regCount = EnumRW(proc, regs, MAX_REG, 1500);
            for (i = 0; i < regCount && nCand < 40; i++) {
                U64 off;
                for (off = 0; off + 0x10000 <= regs[i].Size && nCand < 40; off += 0x10000) {
                    SIZE_T done = 0; ULONG q;
                    RtlZeroMemory(buf, 0x10000);
                    MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(regs[i].Base + off), PsGetCurrentProcess(),
                                        buf, 0x10000, KernelMode, &done);
                    if (done < 0x1000) continue;
                    for (q = 0; q + 8 <= done && nCand < 40; q += 8) {
                        U64 vt = *(U64*)(buf + q), s0, s1, s2, s8;
                        if (vt < modBase || vt >= modBase + modSize || (vt & 7)) continue;
                        if (!NT_SUCCESS(MemRead(proc, vt + 0,  &s0, 8))) continue;
                        if (!NT_SUCCESS(MemRead(proc, vt + 8,  &s1, 8))) continue;
                        if (!NT_SUCCESS(MemRead(proc, vt + 16, &s2, 8))) continue;
                        if (!NT_SUCCESS(MemRead(proc, vt + 64, &s8, 8))) continue;
                        if (s0 < modBase || s0 >= modBase + modSize) continue;
                        if (s1 < modBase || s1 >= modBase + modSize) continue;
                        if (s2 < modBase || s2 >= modBase + modSize) continue;
                        if (s8 < modBase || s8 >= modBase + modSize) continue;
                        if (s0 == s1 || s1 == s2 || s0 == s2) continue;
                        cand[nCand++] = regs[i].Base + off + q;
                    }
                }
            }
            ExFreePoolWithTag(regs, 'regS');
            ExFreePoolWithTag(buf, 'vtbS');
        }
    }
    KLogF("[sc3] qi candidates=%lu\n", nCand);
    if (!nCand) { ExFreePoolWithTag(pay,'qiPS'); ExFreePoolWithTag(tbl,'qiTS'); return FALSE; }

    RtlZeroMemory(tbl, 0x400);
    *(U64*)(tbl + 0x00) = 0;                    /* stage */
    *(U64*)(tbl + 0x08) = oldVal;               /* original QPC */
    *(U64*)(tbl + 0x10) = nCand;
    *(U64*)(tbl + 0x18) = 0x4a0ad2e7310d36a0ull;   /* IID_IDXGISwapChain lo */
    *(U64*)(tbl + 0x20) = 0x6a88b8239d6a04aaull;   /* IID lo 2 */
    for (i = 0; i < nCand; i++) *(U64*)(tbl + 0x40 + i * 8) = cand[i];

    slen = BuildQiStub(stub, tblVa, initVa);
    MemWrite(proc, stubVa, stub, slen);
    MemWrite(proc, initVa, pay, payLen);
    MemWrite(proc, tblVa, tbl, 0x400);

    {   KAPC_STATE apc;
        KeStackAttachProcess(proc, &apc);
        if (PteLoad(pageBase, &pteVal, &pteAddr)) *(U64*)(ULONG_PTR)pteAddr = pteVal & ~(1ULL << 63);
        KeUnstackDetachProcess(&apc);
        FlushTlb(pageBase);
    }

    {   U64 nv = stubVa;
        if (!PatchTargetBytes(proc, slotVa, (const UCHAR*)&nv, 8)) {
            KLog("[sc3] qi: hook failed\n");
            ExFreePoolWithTag(pay,'qiPS'); ExFreePoolWithTag(tbl,'qiTS');
            return FALSE;
        }
    }
    KLogF("[sc3] qi hooked qpc -> stub=0x%llX payload=0x%llX\n", stubVa, initVa);

    for (k = 0; k < 30; k++) {
        U64 ok = 0, obj = 0, vt = 0;
        SleepMs(100);
        MemRead(proc, tblVa + 0x38, &ok, 8);
        if (ok == 0) continue;
        MemRead(proc, tblVa + 0x28, &obj, 8);
        MemRead(proc, tblVa + 0x30, &vt, 8);
        KLogF("[sc3] qi result ok=%Iu obj=0x%llX vtable=0x%llX\n", ok, obj, vt);
        hit = (ok == 1);
        break;
    }

    /* every QI-matching swapchain: patch slot VtSlot on a private copy and measure */
    {
        U64 swapCount = 0, swapObj[8], swapVt[8];
        ULONG si;

        MemRead(proc, tblVa + 0x200, &swapCount, 8);
        if (swapCount > 8) swapCount = 8;
        KLogF("[sc3] qi swapchains=%Iu\n", swapCount);
        for (si = 0; si < swapCount; si++) {
            MemRead(proc, tblVa + 0x180 + si * 8, &swapObj[si], 8);
            MemRead(proc, tblVa + 0x1C0 + si * 8, &swapVt[si], 8);
            KLogF("[sc3] qi sc[%lu] obj=0x%llX vtable=0x%llX\n", si, swapObj[si], swapVt[si]);
        }

        for (si = 0; si < swapCount && !hit; si++) {
            UCHAR vt[0x100];
            UCHAR fs[32];
            ULONG fslen, sl = j->VtSlot ? j->VtSlot : 22;
            U64 origSlot = 0, c1 = 0, c2 = 0, rate = 0, copyAddr = pageBase + 0xC00, origVt;

            if (!NT_SUCCESS(MemRead(proc, swapVt[si], vt, sizeof(vt)))) continue;
            if (!NT_SUCCESS(MemRead(proc, swapVt[si] + sl * 8, &origSlot, 8))) continue;
            if (origSlot < modBase || origSlot >= modBase + modSize) {
                KLogF("[sc3] qi sc[%lu] slot%lu not in dxgi (0x%llX), skip\n", si, sl, origSlot);
                continue;
            }
            fslen = BuildFwdStub2(fs, tblVa);
            MemWrite(proc, pageBase + 0xB00, fs, fslen);
            *(U64*)(vt + sl * 8) = pageBase + 0xB00;
            MemWrite(proc, pageBase + 0xC00, vt, sizeof(vt));
            { U64 t2[2]; t2[0] = origSlot; t2[1] = 0; MemWrite(proc, tblVa + 0x208, t2, 16); }

            origVt = swapVt[si];
            if (!NT_SUCCESS(MemWrite(proc, swapObj[si], &copyAddr, 8))) {
                KLogF("[sc3] qi sc[%lu] repoint failed\n", si);
                continue;
            }
            MemRead(proc, tblVa + 0x210, &c1, 8);
            SleepMs(1000);
            MemRead(proc, tblVa + 0x210, &c2, 8);
            rate = c2 - c1;
            KLogF("[sc3] qi sc[%lu] slot%lu rate=%Iu/s\n", si, sl, rate);
            if (rate >= 30 && rate <= 400) {
                hit = TRUE;
                KLogF("[sc3] QI PRESENT MATCH obj=0x%llX vtable=0x%llX slot=%lu\n", swapObj[si], swapVt[si], sl);
            }
            if (!NT_SUCCESS(MemWrite(proc, swapObj[si], &origVt, 8)))
                KLogF("[sc3] qi sc[%lu] restore FAILED\n", si);
        }
    }

    /* last internal door: find where the engine cached Present/Present1 */
    {
        U64 vt0 = 0, v8 = 0, v22 = 0;
        MemRead(proc, tblVa + 0x1C0, &vt0, 8);
        if (vt0) {
            if (NT_SUCCESS(MemRead(proc, vt0 + 8 * 8, &v8, 8)))
                ScanForValue(proc, v8, "slot8", 6);
            if (NT_SUCCESS(MemRead(proc, vt0 + 22 * 8, &v22, 8)))
                ScanForValue(proc, v22, "slot22", 6);
        }
    }

    {   U64 r;
        if (!PatchTargetBytes(proc, slotVa, (const UCHAR*)&oldVal, 8)) KLog("[sc3] qi: restore FAILED\n");
        else KLog("[sc3] qi restored\n");
        (void)r;
    }
    ExFreePoolWithTag(pay, 'qiPS');
    ExFreePoolWithTag(tbl, 'qiTS');
    return hit;
}

/* read-only: find slots holding a cached function pointer (dxgi_base + rel) */
static VOID ScanCachedPtr(PEPROCESS proc, JOB* j)
{
    REG* regs;
    UCHAR* buf;
    ULONG regCount, i, hits = 0;
    U64 modBase, modSize = 0, target;

    modBase = TargetModuleBase(proc, j->VtMod[0] ? j->VtMod : L"dxgi.dll");
    if (modBase) {
        KAPC_STATE apc; U64 nt;
        KeStackAttachProcess(proc, &apc);
        nt = modBase + *(ULONG*)(ULONG_PTR)(modBase + 0x3C);
        modSize = *(ULONG*)(ULONG_PTR)(nt + 0x50);
        KeUnstackDetachProcess(&apc);
    }
    if (!modBase || !modSize || !j->CacheVal) return;
    target = modBase + j->CacheVal;
    KLogF("[sc3] cache scan target=0x%llX (dxgi+0x%X)\n", target, j->CacheVal);

    regs = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(REG) * MAX_REG, 'regS');
    buf  = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'vtbS');
    if (!regs || !buf) { if (regs) ExFreePoolWithTag(regs,'regS'); if (buf) ExFreePoolWithTag(buf,'vtbS'); return; }

    regCount = EnumRW(proc, regs, MAX_REG, 1500);
    for (i = 0; i < regCount && hits < 40; i++) {
        U64 off;
        for (off = 0; off + 0x10000 <= regs[i].Size && hits < 40; off += 0x10000) {
            SIZE_T done = 0; ULONG k;
            RtlZeroMemory(buf, 0x10000);
            MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(regs[i].Base + off), PsGetCurrentProcess(),
                                buf, 0x10000, KernelMode, &done);
            if (done < 0x1000) continue;
            for (k = 0; k + 8 <= done && hits < 40; k += 8) {
                if (*(U64*)(buf + k) == target) {
                    KLogF("[sc3] cache hit at 0x%llX\n", regs[i].Base + off + k);
                    hits++;
                }
            }
        }
    }
    KLogF("[sc3] cache scan hits=%lu\n", hits);
    ExFreePoolWithTag(regs, 'regS');
    ExFreePoolWithTag(buf, 'vtbS');
}

/* ---------------- engine present hook by pattern ----------------
   pattern 1 (dx12 present wrapper, verified boundary-safe: the 12 bytes are
   exactly push rbx / sub rsp,0x840 / mov rax,[rdx]):
     40 53 48 81 EC 40 08 00 00 48 8B 02 ...
   hook: 48 B8 <payload> FF E0   (12 bytes)
   payload: <12 original bytes> / movabs r11,table / inc [r11+8] / mov rax,[r11+0x10] / jmp rax
*/
#define W(x) ((USHORT)(0xFF00 | (x)))
#define WILD 0xFFFF
static const USHORT g_pat1[] = {
    W(0x40), W(0x53), W(0x48), W(0x81), W(0xEC), W(0x40), W(0x08), W(0x00), W(0x00), W(0x48), W(0x8B), W(0x02), W(0x44), W(0x0F), W(0xB6), W(0x4A), W(0x0C), W(0x48), W(0x8B), W(0x48), W(0x30), W(0x41), W(0x0F), W(0xB6), W(0xC1), W(0xF6), W(0xD8), W(0x45), W(0x1B), W(0xC0), W(0x33), W(0xD2), W(0x4C), W(0x8B), W(0x11)
};
/* pattern 2 (SpinPresent) with ?? wildcards marked by 0xFF00|byte, 0xFFFF = ?? */
static const USHORT g_pat2[] = {
    W(0x40),W(0x53),W(0x48),W(0x83),W(0xEC),W(0x20),W(0xFF),W(0x05),WILD,WILD,WILD,WILD,
    W(0x8B),W(0x1D),WILD,WILD,WILD,WILD,W(0xE8),WILD,WILD,WILD,WILD,
    W(0x84),W(0xC0),W(0x74),WILD,W(0x8D),W(0x53),W(0xFF),W(0xB9),W(0x04),W(0x00),W(0x00),W(0x00),W(0xE8)
};

/* scan every executable section (not just .text) for a byte pattern */
static U64 ScanTextForPattern(PEPROCESS proc, U64 base, const USHORT* pat, ULONG len)
{
    U64 nt, hit = 0;
    KAPC_STATE apc;
    UCHAR* buf = NULL;
    ULONG i, nsec, so;

    KeStackAttachProcess(proc, &apc);
    nt = base + *(ULONG*)(ULONG_PTR)(base + 0x3C);
    nsec = *(USHORT*)(ULONG_PTR)(nt + 6);
    so = *(USHORT*)(ULONG_PTR)(nt + 20);
    KLogF("[sc3] pat: sections=%lu\n", nsec);

    buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x100000, 'patS');
    if (!buf) { KeUnstackDetachProcess(&apc); return 0; }

    for (i = 0; i < nsec && !hit; i++) {
        PUCHAR sh = (PUCHAR)(nt + 24 + so + i * 40);
        ULONG vsize = *(ULONG*)(sh + 8);
        ULONG rva = *(ULONG*)(sh + 12);
        ULONG chars = *(ULONG*)(sh + 36);
        U64 secVa = base + rva;
        ULONG off;
        char nm[9];

        RtlZeroMemory(nm, sizeof(nm));
        RtlCopyMemory(nm, sh, 8);
        if (!(chars & 0x20000000)) continue;          /* IMAGE_SCN_MEM_EXECUTE */
        if (vsize < 0x1000) continue;
        KLogF("[sc3] pat: exec section %s va=0x%llX size=0x%X\n", nm, secVa, vsize);

        for (off = 0; off + 0x1000 < vsize && !hit; off += 0x100000) {
            ULONG chunk = (vsize - off > 0x100000) ? 0x100000 : (vsize - off);
            ULONG k, j;
            {
                NTSTATUS rst;
                RtlZeroMemory(buf, 0x100000);
                rst = MemRead(proc, secVa + off, buf, chunk);
                if (!NT_SUCCESS(rst)) {
                    /* retry smaller */
                    ULONG sub;
                    for (sub = 0; sub + 0x10000 <= chunk; sub += 0x10000)
                        MemRead(proc, secVa + off + sub, buf + sub, 0x10000);
                }
            }
            for (j = 0; j + len * 2 <= chunk && !hit; j++) {
                ULONG ok = 1;
                for (k = 0; k < len; k++) {
                    USHORT w = pat[k];
                    if (w == WILD) continue;
                    if (buf[j + k] != (UCHAR)(w & 0xFF)) { ok = 0; break; }
                }
                if (ok) { hit = secVa + off + j; KLogF("[sc3] pat: found in %s +0x%X\n", nm, off + j); }
            }
        }
    }
    KeUnstackDetachProcess(&apc);
    if (buf) ExFreePoolWithTag(buf, 'patS');
    return hit;
}

static ULONG BuildPresentStub(UCHAR* sc, U64 tableVa, const UCHAR* orig)
{
    ULONG k = 0, i;
    for (i = 0; i < 12; i++) sc[k++] = orig[i];          /* original bytes   */
    sc[k++] = 0x49; sc[k++] = 0xBB;
    *(U64*)(sc + k) = tableVa; k += 8;                   /* movabs r11,table */
    sc[k++] = 0x49; sc[k++] = 0xFF; sc[k++] = 0x43; sc[k++] = 0x08;  /* inc [r11+8] */
    sc[k++] = 0x49; sc[k++] = 0x8B; sc[k++] = 0x43; sc[k++] = 0x10;  /* mov rax,[r11+0x10] */
    sc[k++] = 0xFF; sc[k++] = 0xE0;                      /* jmp rax          */
    return k;
}

static BOOLEAN DoPatHook(PEPROCESS proc, JOB* j, SCAN* s)
{
    SLOT* best = NULL;
    U64 base, hit, pageBase, tblVa, pteVal = 0, pteAddr = 0;
    UCHAR orig[12], stub[64], jmp[12];
    ULONG i, slen;
    BOOLEAN ok = FALSE;
    U64 cnt = 0;

    for (i = 0; i < s->Total; i++)
        if (s->Slots[i].Verified && (!best || s->Slots[i].Score > best->Score)) best = &s->Slots[i];
    if (!best) { KLog("[sc3] pat: no zero page\n"); return FALSE; }

    base = TargetModuleBase(proc, j->Name[0] ? j->Name : L"r5apex_dx12.exe");
    if (!base) { KLog("[sc3] pat: module not found\n"); return FALSE; }

    hit = ScanTextForPattern(proc, base, g_pat1, RTL_NUMBER_OF(g_pat1));
    KLogF("[sc3] pat1 (present wrapper) hit=0x%llX\n", hit);
    if (!hit) {
        hit = ScanTextForPattern(proc, base, g_pat2, RTL_NUMBER_OF(g_pat2));
        KLogF("[sc3] pat2 (spinpresent) hit=0x%llX\n", hit);
    }
    if (!hit) { KLog("[sc3] pat: patterns not found (version changed?)\n"); return FALSE; }

    if (!NT_SUCCESS(MemRead(proc, hit, orig, 12))) { KLog("[sc3] pat: read site failed\n"); return FALSE; }
    KLogF("[sc3] pat site bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
          orig[0],orig[1],orig[2],orig[3],orig[4],orig[5],orig[6],orig[7],orig[8],orig[9],orig[10],orig[11]);

    pageBase = best->Page;
    tblVa = pageBase + 0x400;
    slen = BuildPresentStub(stub, tblVa, orig);
    { U64 t[4]; t[0] = 0; t[1] = 0; t[2] = hit + 12; t[3] = 0; MemWrite(proc, tblVa, t, sizeof(t)); }
    if (!NT_SUCCESS(MemWrite(proc, pageBase, stub, slen))) { KLog("[sc3] pat: stub write failed\n"); return FALSE; }

    {   KAPC_STATE apc;
        KeStackAttachProcess(proc, &apc);
        if (PteLoad(pageBase, &pteVal, &pteAddr)) *(U64*)(ULONG_PTR)pteAddr = pteVal & ~(1ULL << 63);
        KeUnstackDetachProcess(&apc);
        FlushTlb(pageBase);
    }

    jmp[0] = 0x48; jmp[1] = 0xB8;
    *(U64*)(jmp + 2) = pageBase;
    jmp[10] = 0xFF; jmp[11] = 0xE0;
    if (!PatchTargetBytes(proc, hit, jmp, 12)) { KLog("[sc3] pat: hook failed\n"); return FALSE; }
    KLogF("[sc3] pat hooked 0x%llX -> payload 0x%llX\n", hit, pageBase);

    for (i = 0; i < 50; i++) {
        SleepMs(200);
        MemRead(proc, tblVa + 0x08, &cnt, 8);
        if (cnt) break;
    }
    KLogF("[sc3] pat beats=%Iu\n", cnt);
    ok = (cnt > 0);

    if (!PatchTargetBytes(proc, hit, orig, 12)) KLog("[sc3] pat: RESTORE FAILED\n");
    else KLog("[sc3] pat restored\n");
    return ok;
}

/* ---------------- creation-time capture: hook dxgi!CreateDXGIFactory2 ----------------
   stub (5th arg of CreateDXGIFactory2 is ppFactory, at [rsp+0x28] on entry):
       push rbx / sub rsp,0x30
       mov rax,[rsp+0x58] / mov [rsp+0x20],rax   ; forward 5th arg
       movabs rbx,table / mov rax,[rbx]          ; original
       call rax
       movabs rbx,table / mov rcx,[rsp+0x20]
       test rcx,rcx / jz done / mov rcx,[rcx] / mov [rbx+8],rcx
     done: add rsp,0x30 / pop rbx / ret
   table+0x00 = original, table+0x08 = captured factory
*/
static ULONG BuildFactoryStub(UCHAR* sc, U64 tableVa)
{
    ULONG k = 0, jzAt;

    sc[k++] = 0x53;                                             /* push rbx        */
    sc[k++] = 0x48; sc[k++] = 0x83; sc[k++] = 0xEC; sc[k++] = 0x30;
    sc[k++] = 0x48; sc[k++] = 0x8B; sc[k++] = 0x84; sc[k++] = 0x24;
    *(ULONG*)(sc + k) = 0x58; k += 4;                           /* mov rax,[rsp+0x58] */
    sc[k++] = 0x48; sc[k++] = 0x89; sc[k++] = 0x84; sc[k++] = 0x24;
    *(ULONG*)(sc + k) = 0x20; k += 4;                           /* mov [rsp+0x20],rax */
    sc[k++] = 0x48; sc[k++] = 0xBB;
    *(U64*)(sc + k) = tableVa; k += 8;
    sc[k++] = 0x48; sc[k++] = 0x8B; sc[k++] = 0x03;             /* mov rax,[rbx]   */
    sc[k++] = 0xFF; sc[k++] = 0xD0;                             /* call rax        */
    sc[k++] = 0x48; sc[k++] = 0xBB;
    *(U64*)(sc + k) = tableVa; k += 8;
    sc[k++] = 0x48; sc[k++] = 0x8B; sc[k++] = 0x8C; sc[k++] = 0x24;
    *(ULONG*)(sc + k) = 0x20; k += 4;                           /* mov rcx,[rsp+0x20] */
    sc[k++] = 0x48; sc[k++] = 0x85; sc[k++] = 0xC9;             /* test rcx,rcx    */
    sc[k++] = 0x74; jzAt = k; k++;                              /* jz done         */
    sc[k++] = 0x48; sc[k++] = 0x8B; sc[k++] = 0x09;             /* mov rcx,[rcx]   */
    sc[k++] = 0x48; sc[k++] = 0x89; sc[k++] = 0x4B; sc[k++] = 0x08;  /* mov [rbx+8],rcx */
    sc[jzAt] = (UCHAR)(k - (jzAt + 1));
    sc[k++] = 0x48; sc[k++] = 0x83; sc[k++] = 0xC4; sc[k++] = 0x30;
    sc[k++] = 0x5B;                                             /* pop rbx         */
    sc[k++] = 0xC3;
    return k;
}

static BOOLEAN DoFactoryCapture(PEPROCESS proc, JOB* j, SCAN* s)
{
    SLOT* best = NULL;
    U64 pageBase, tblVa, slotVa = 0, oldVal = 0, pteVal = 0, pteAddr = 0;
    UCHAR stub[128];
    ULONG i, slen;
    U64 fac = 0;

    for (i = 0; i < s->Total; i++)
        if (s->Slots[i].Verified && (!best || s->Slots[i].Score > best->Score)) best = &s->Slots[i];
    if (!best) { KLog("[sc3] fac: no zero page\n"); return FALSE; }

    {   ULONG try_;
        for (try_ = 0; try_ < 40 && !slotVa; try_++) {
            slotVa = IatFindSlot(proc, j->IatMod[0] ? j->IatMod : j->Name, L"dxgi.dll",
                                 L"CreateDXGIFactory2", &oldVal);
            if (!slotVa) SleepMs(50);
        }
    }
    if (!slotVa) { KLog("[sc3] fac: CreateDXGIFactory2 IAT not found\n"); return FALSE; }
    KLogF("[sc3] fac iat slot=0x%llX old=0x%llX\n", slotVa, oldVal);

    pageBase = best->Page;
    tblVa = pageBase + 0x400;
    slen = BuildFactoryStub(stub, tblVa);
    { U64 t[4]; t[0] = oldVal; t[1] = 0; t[2] = 0; t[3] = 0; MemWrite(proc, tblVa, t, sizeof(t)); }
    MemWrite(proc, pageBase, stub, slen);

    {   KAPC_STATE apc;
        KeStackAttachProcess(proc, &apc);
        if (PteLoad(pageBase, &pteVal, &pteAddr)) *(U64*)(ULONG_PTR)pteAddr = pteVal & ~(1ULL << 63);
        KeUnstackDetachProcess(&apc);
        FlushTlb(pageBase);
    }
    {   U64 nv = pageBase;
        if (!PatchTargetBytes(proc, slotVa, (const UCHAR*)&nv, 8)) {
            KLog("[sc3] fac: iat hook failed\n");
            return FALSE;
        }
    }
    KLog("[sc3] fac: iat hooked, waiting for factory creation\n");

    for (i = 0; i < 150; i++) {
        SleepMs(100);
        MemRead(proc, tblVa + 0x08, &fac, 8);
        if (fac) break;
    }
    KLogF("[sc3] fac: captured factory=0x%llX (after %lu ms)\n", fac, i * 100);

    if (fac) {
        U64 vt = 0;
        MemRead(proc, fac, &vt, 8);
        KLogF("[sc3] fac: factory vtable=0x%llX\n", vt);
    }
    return fac != 0;
}

/* ---------------- early capture: act from the process-creation callback ----------------
   polling for the process is too slow (the game builds its DXGI factory first), so we
   register a create-process notify and start work the moment the image appears.
*/
static JOB g_job;
static volatile LONG g_busy = 0;

static VOID EarlyWorker(PVOID ctx)
{
    ULONG pid = (ULONG)(ULONG_PTR)ctx;
    PEPROCESS proc = NULL;
    NTSTATUS st;
    ULONG tries;
    U64 slotVa = 0, oldVal = 0;

    KLogF("[sc3] early: worker for pid=%lu\n", pid);
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    if (!NT_SUCCESS(st)) { KLogF("[sc3] early: lookup=0x%X\n", st); PsTerminateSystemThread(st); }

    /* wait for the loader to resolve imports, then grab the IAT slot asap */
    for (tries = 0; tries < 400 && !slotVa; tries++) {
        slotVa = IatFindSlot(proc, g_job.Name[0] ? g_job.Name : L"r5apex_dx12.exe",
                             L"dxgi.dll", L"CreateDXGIFactory2", &oldVal);
        if (!slotVa) SleepMs(5);
    }
    KLogF("[sc3] early: iat slot=0x%llX old=0x%llX after %lu ms\n", slotVa, oldVal, tries * 5);
    if (slotVa) {
        SCAN sc;
        if (g_job.VtWait) SleepMs(g_job.VtWait * 1000);
        ScanOnce(proc, &g_job, &sc, 4);
        if (sc.Verified > 0) {
            BOOLEAN ok = DoFactoryCapture(proc, &g_job, &sc);
            KLog(ok ? "[sc3] EARLY FACTORY CAPTURED\n" : "[sc3] early: factory not captured\n");
        } else KLog("[sc3] early: no zero page\n");
    }
    ObDereferenceObject(proc);
    InterlockedExchange(&g_busy, 0);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID CreateProcNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO Info)
{
    UNICODE_STRING* img;
    HANDLE h = NULL;

    if (!Info) return;                       /* exit notification */
    img = Info->ImageFileName;
    if (!img || !img->Buffer) return;
    if (!RtlEqualUnicodeString(img, &(UNICODE_STRING){ 30, 32, L"r5apex_dx12.exe" }, TRUE)) return;
    if (InterlockedExchange(&g_busy, 1) != 0) return;
    KLogF("[sc3] notify: %ws created pid=%lu\n", img->Buffer, (ULONG)(ULONG_PTR)ProcessId);
    if (!NT_SUCCESS(PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, EarlyWorker,
                                         (PVOID)(ULONG_PTR)ProcessId)) && h) ZwClose(h);
}

static VOID Run(PEPROCESS proc, JOB* j)
{
    ULONG64 ntBase, dirBase;
    SCAN scan;
    ULONG attempt, i, tCount, tids[16];

    ntBase = FindNtBase();
    g_PteBase = ReadPteBase(ntBase);
    g_UseIpi = j->UseIpi;
    dirBase = *(ULONG64*)((PUCHAR)proc + 0x28);
    KLogF("[sc3] nt=0x%llX pteBase=0x%llX dirBase=0x%llX phase=%lu retries=%lu\n",
          ntBase, g_PteBase, dirBase, j->Phase, j->Retries);
    if (!g_PteBase) { KLog("[sc3] pteBase not found, abort\n"); return; }

    if (j->FactoryMode) {
        SCAN sc5;
        ScanOnce(proc, j, &sc5, 4);
        if (sc5.Verified > 0) {
            BOOLEAN ok = DoFactoryCapture(proc, j, &sc5);
            KLog(ok ? "[sc3] FACTORY CAPTURED\n" : "[sc3] fac: not captured\n");
        } else KLog("[sc3] fac: no zero page\n");
        return;
    }

    if (j->PatHook) {
        SCAN sc4;
        if (j->VtWait) { KLogF("[sc3] pat: waiting %lu s\n", j->VtWait); SleepMs(j->VtWait * 1000); }
        ScanOnce(proc, j, &sc4, 4);
        if (sc4.Verified > 0) {
            BOOLEAN ok = DoPatHook(proc, j, &sc4);
            KLog(ok ? "[sc3] PRESENT HOOK OK\n" : "[sc3] pat: no beats\n");
        } else KLog("[sc3] pat: no zero page\n");
        return;
    }

    if (j->CacheScan) {
        ScanCachedPtr(proc, j);
        KLog("[sc3] cache scan done\n");
        return;
    }

    if (j->QiTest) {
        SCAN sc3s;
        if (j->VtWait) { KLogF("[sc3] qi: waiting %lu s before scan\n", j->VtWait); SleepMs(j->VtWait * 1000); }
        ScanOnce(proc, j, &sc3s, 4);
        if (sc3s.Verified > 0) {
            BOOLEAN ok = DoQiTest(proc, j, &sc3s);
            KLog(ok ? "[sc3] QI SWAPCHAIN FOUND\n" : "[sc3] qi: no swapchain among candidates\n");
        } else {
            KLog("[sc3] qi: no zero page\n");
        }
        return;
    }

    if (j->VtTrial) {
        SCAN sc2;
        if (j->VtWait) { KLogF("[sc3] vt: waiting %lu s before trial\n", j->VtWait); SleepMs(j->VtWait * 1000); }
        ScanOnce(proc, j, &sc2, 4);
        if (sc2.Verified > 0) {
            BOOLEAN ok = DoVtTrial(proc, j, &sc2);
            KLog(ok ? "[sc3] VTABLE HIT\n" : "[sc3] vt trial: no match\n");
        } else {
            KLog("[sc3] vt: no zero page available\n");
        }
        return;
    }

    if (j->VtScan) {
        ScanVtable(proc, j->VtMod[0] ? j->VtMod : L"dxgi.dll");
        KLog("[sc3] vtscan done\n");
        return;
    }

    if (j->ImpDump) {
        DumpImports(proc, j->Name[0] ? j->Name : L"r5apex_dx12.exe");
        KLog("[sc3] impdump done\n");
        return;
    }

    /* note: the unhook happens right before the loader (inside DoInject).
       doing it here as well leaves the hooks missing for the whole scan and
       that window is what gets noticed. */

    for (attempt = 0; attempt <= j->Retries; attempt++) {
        if (PsGetProcessExitStatus(proc) != STATUS_PENDING) { KLog("[sc3] target exited, stop\n"); break; }
        KLogF("[sc3] === attempt %lu ===\n", attempt);
        ScanOnce(proc, j, &scan, (attempt == 0) ? 8 : 3);

        if (attempt == 0 && j->Phase >= 2) {
            tCount = GetWaitingThreads(j->Pid, tids, 16, TRUE);
            KLogF("[sc3] waiting threads=%lu\n", tCount);
        }
        if (j->Phase < 3) break;

        if (j->IatApi[0] && scan.Verified > 0) {
            BOOLEAN ok = DoIat(proc, j, &scan);
            KLog(ok ? "[sc3] IAT TRIGGER OK\n" : "[sc3] iat attempt done\n");
            break;
        }
        if (j->WndInst) {
            if (scan.Verified > 0) {
                BOOLEAN ok = DoWnd(proc, j, &scan);
                if (ok) KLog("[sc3] TRIGGER OK\n");
                else KLog("[sc3] wnd attempt done\n");
                break;
            }
        }
        if (j->HookN && !j->HookForce) {
            KLog("[sc3] hook mode refused: image code pages are shared across processes.\n");
            KLog("[sc3]   patching them via pte poisons every process that maps the page (bugcheck 0xEF).\n");
            KLog("[sc3]   use a process-local trigger instead (wndproc / vtable pointer / apc).\n");
            break;
        }
        if (scan.Verified > 0) {
            BOOLEAN ok = j->HookN ? DoHook(proc, j, &scan) : DoInject(proc, j, &scan);
            if (ok) KLog("[sc3] TRIGGER OK\n");
            else KLog("[sc3] trigger attempt failed\n");
            break;
        }
        KLogF("[sc3] no verified slot, retry in %lu ms\n", j->RetryGap);
        SleepMs(j->RetryGap);
    }
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl, ct, ct2;
    ULONG waited = 0, pid = 0, last = 0, stable = 0;
    PEPROCESS proc = NULL;
    NTSTATUS st;
    UCHAR jobBuf[1024];
    ULONG jobLen = 0;
    JOB j;

    UNREFERENCED_PARAMETER(ctx);
    ct.QuadPart = 0;
    KLog("[sc3] waiter alive\n");
    if (!NT_SUCCESS(ReadJob(jobBuf, sizeof(jobBuf) - 1, &jobLen))) {
        KLog("[sc3] read job failed\n");
        PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
    }
    ParseJob(jobBuf, jobLen, &j);
    KLogF("[sc3] job pid=%lu phase=%lu samples=%lu gap=%lu ipi=%lu\n",
          j.Pid, j.Phase, j.Samples, j.Gap, j.UseIpi);

    if (j.Pid == 0) {
        for (;;) {
            pid = FindPid(j.Name, &ct2);
            { ULONG pm = j.PollMs ? j.PollMs : 500;
              if (pid && pid == last && ct2.QuadPart == ct.QuadPart) stable += pm;
              else { last = pid; ct = ct2; stable = 0; }
              if (pid && stable >= (j.SettleMs ? j.SettleMs : (ULONG)SETTLE_SEC * 1000)) break;
              dl.QuadPart = -((LONGLONG)pm * 10000LL); waited += pm; }
            KeDelayExecutionThread(KernelMode, FALSE, &dl);
            if (waited > 1800000) {
                KLog("[sc3] timeout\n");
                PsTerminateSystemThread(STATUS_TIMEOUT);
            }
        }
        j.Pid = pid;
    }
    KLogF("[sc3] target pid=%lu\n", j.Pid);

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)j.Pid, &proc);
    if (!NT_SUCCESS(st)) {
        KLogF("[sc3] lookup=0x%X\n", st);
        PsTerminateSystemThread(st);
    }

    Run(proc, &j);

    ObDereferenceObject(proc);
    KLog("[sc3] done\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h = NULL;
    NTSTATUS st;
    UNREFERENCED_PARAMETER(D);
    UNREFERENCED_PARAMETER(R);
    KLog("\n[sc3] === entry ===\n");
    {   UCHAR jb[1024]; ULONG jl = 0;
        if (NT_SUCCESS(ReadJob(jb, sizeof(jb) - 1, &jl))) {
            ParseJob(jb, jl, &g_job);
            if (g_job.FactoryMode) {
                NTSTATUS rs = PsSetCreateProcessNotifyRoutine((PVOID)CreateProcNotify, FALSE);
                KLogF("[sc3] notify register=0x%X\n", rs);
            }
        }
    }
    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, Waiter, NULL);
    if (NT_SUCCESS(st) && h) ZwClose(h);
    KLogF("[sc3] thread=0x%X\n", st);
    {
        LARGE_INTEGER d;
        d.QuadPart = -30000000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &d);
    }
    return STATUS_SUCCESS;
}
