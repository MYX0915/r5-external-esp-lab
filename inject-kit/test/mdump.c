// mdump.sys -- two-pass memory dumper for offline analysis
//   pass 1: module .data/.rdata + RW private heap regions -> C:\ProgramData\scdump\p1_*.bin
//   (user rotates/moves for 8s)
//   pass 2: same regions -> p2_*.bin
//   manifest: C:\ProgramData\scdump\manifest.txt  (va size file)
#include <ntifs.h>
#include <ntstrsafe.h>
#include <string.h>

#define FEED_MAX_ENT 24
static PEPROCESS g_espProc = NULL;
static ULONG g_entCount = 0;
static float g_entList[FEED_MAX_ENT][3];
#define TGT_ALIVE() (g_espProc && PsGetProcessExitStatus(g_espProc) == STATUS_PENDING)
static CHAR* AppendFmt(CHAR* p, CHAR* end, const CHAR* fmt, ...);



#define LOG_FILE L"\\??\\C:\\ProgramData\\kmaplog.txt"
#define OUT_DIR  L"\\??\\C:\\ProgramData\\scdump\\"

typedef unsigned __int64 U64;

static U64   g_entAddr[64];
static ULONG g_entAddrCount = 0;
static ULONG g_espMode = 1;   /* 0=????? vtable?  1=???? */

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
NTSYSAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T);
NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS);
NTSYSAPI PVOID NTAPI MmGetSystemRoutineAddress(PUNICODE_STRING);

typedef struct _SPID { ULONG Next; ULONG Threads; LARGE_INTEGER W; ULONG HF; ULONG HW;
    ULONGLONG CT; LARGE_INTEGER Cr; LARGE_INTEGER U; LARGE_INTEGER K; UNICODE_STRING ImageName;
    LONG BP; HANDLE PID; } SPID, *PSPID;

typedef struct _MBINF { PVOID Base; PVOID AllocBase; ULONG AllocProt; ULONG Pad0; SIZE_T Size;
    ULONG State; ULONG Protect; ULONG Type; ULONG Pad1; } MBINF;

#define DUMP_CHUNK 0x00800000u   /* 8MB: every copy is capped to this */
typedef struct _REG { U64 Base; U64 Size; } REG;
#define MAX_REG 2000

static FAST_MUTEX g_ioMutex;
static HANDLE g_feedHandle = NULL;

static VOID WA(PCWSTR f2, PCSTR t, ULONG len){ UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    RtlInitUnicodeString(&p,f2); InitializeObjectAttributes(&oa,&p,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);
    {
        LARGE_INTEGER t0; t0.QuadPart = 0;
        if(NT_SUCCESS(ZwCreateFile(&h,FILE_APPEND_DATA|SYNCHRONIZE,&oa,&io,NULL,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_OPEN_IF,FILE_SYNCHRONOUS_IO_NONALERT,NULL,0))) {
            ZwWriteFile(h,NULL,NULL,NULL,&io,(PVOID)t,len,NULL,NULL); ZwFlushBuffersFile(h,&io); ZwClose(h);
        }
        (void)t0;
    } }
static VOID K(PCSTR t){ size_t n=0; RtlStringCchLengthA(t,2048,&n); WA(LOG_FILE,t,(ULONG)n); }
static VOID KF(PCSTR f,...){ CHAR b[400]; va_list ap; va_start(ap,f); RtlStringCchVPrintfA(b,sizeof(b),f,ap); va_end(ap); K(b); }

static ULONG FindPid(PCWSTR name, LARGE_INTEGER* oc)
{
    ULONG size=1<<20,ret=0,res=0; PVOID buf; NTSTATUS st; UNICODE_STRING want;
    buf=ExAllocatePool2(POOL_FLAG_NON_PAGED,size,'pmiK'); if(!buf) return 0;
    st=ZwQuerySystemInformation(5,buf,size,&ret);
    if(st==STATUS_INFO_LENGTH_MISMATCH&&ret>size){ ExFreePoolWithTag(buf,'pmiK'); size=ret+0x1000;
        buf=ExAllocatePool2(POOL_FLAG_NON_PAGED,size,'pmiK'); if(!buf) return 0;
        st=ZwQuerySystemInformation(5,buf,size,&ret); }
    if(!NT_SUCCESS(st)){ ExFreePoolWithTag(buf,'pmiK'); return 0; }
    RtlInitUnicodeString(&want,name);
    { PUCHAR p=(PUCHAR)buf;
      for(;;){ PSPID e=(PSPID)p;
        if(e->ImageName.Buffer&&e->ImageName.Length){ UNICODE_STRING u=e->ImageName;
            if(RtlEqualUnicodeString(&u,&want,TRUE)){ res=(ULONG)(ULONG_PTR)e->PID; if(oc)*oc=e->Cr; break; } }
        if(!e->Next) break; p+=e->Next; } }
    ExFreePoolWithTag(buf,'pmiK'); return res;
}

static void SleepMs(ULONG ms){ LARGE_INTEGER d; d.QuadPart = -((LONGLONG)ms*10000LL); KeDelayExecutionThread(KernelMode,FALSE,&d); }

static VOID WriteFileAt(PCWSTR path, PVOID buf, ULONG len)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    RtlInitUnicodeString(&p,path);
    InitializeObjectAttributes(&oa,&p,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);
    if(!NT_SUCCESS(ZwCreateFile(&h,GENERIC_WRITE|SYNCHRONIZE,&oa,&io,NULL,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ,FILE_OVERWRITE_IF,FILE_SYNCHRONOUS_IO_NONALERT,NULL,0))) return;
    ZwWriteFile(h,NULL,NULL,NULL,&io,buf,len,NULL,NULL);
    ZwClose(h);
}


/* copy [va, va+len) into path in DUMP_CHUNK pieces -- buffer stays 8MB, region can be big */
#define REGION_CAP 0x04000000u   /* 64MB per region */
static ULONG DumpRegionToFile(PEPROCESS proc, U64 va, ULONG len, PUCHAR buf, PCWSTR path)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    UNICODE_STRING mp; OBJECT_ATTRIBUTES moa; IO_STATUS_BLOCK mio; HANDLE mh = NULL;
    WCHAR metaPath[160];
    ULONG done_total = 0, okChunks = 0, badChunks = 0, firstBad = 0xFFFFFFFF;

    if (len > REGION_CAP) len = REGION_CAP;
    RtlInitUnicodeString(&p, path);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, GENERIC_WRITE | SYNCHRONIZE, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL,
                                 FILE_SHARE_READ, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
        return 0;

    /* ---- sidecar status file: <path>.meta ---- */
    {
        ULONG i = 0;
        while (path[i] && i < 140) { metaPath[i] = path[i]; i++; }
        metaPath[i++] = L'.'; metaPath[i++] = L'm'; metaPath[i++] = L'e';
        metaPath[i++] = L't'; metaPath[i++] = L'a'; metaPath[i] = 0;
        RtlInitUnicodeString(&mp, metaPath);
        InitializeObjectAttributes(&moa, &mp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        if (!NT_SUCCESS(ZwCreateFile(&mh, GENERIC_WRITE | SYNCHRONIZE, &moa, &mio, NULL, FILE_ATTRIBUTE_NORMAL,
                                     FILE_SHARE_READ, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
            mh = NULL;
        if (mh) {
            CHAR* hdr = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x200, 'dpMH');
            if (hdr) {
                CHAR* w = AppendFmt(hdr, hdr + 0x200,
                    "#!/ mdump meta\nva=0x%llX len=0x%X\n#chunk_off status got want\n", va, len);
                ZwWriteFile(mh, NULL, NULL, NULL, &mio, hdr, (ULONG)(w - hdr), NULL, NULL);
                ExFreePoolWithTag(hdr, 'dpMH');
            }
        }
    }

    while (done_total < len) {
        ULONG chunk = len - done_total;
        SIZE_T got = 0;
        NTSTATUS st;
        if (chunk > 0x10000) chunk = 0x10000;      /* 64KB steps: one bad page never kills the range */
        RtlZeroMemory(buf, chunk);
        st = MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(va + done_total), PsGetCurrentProcess(),
                                 buf, chunk, KernelMode, &got);
        if (!NT_SUCCESS(st) || got != chunk) {
            /* keep zeros in the data file, but record the truth in the meta sidecar */
            badChunks++;
            if (firstBad == 0xFFFFFFFF) firstBad = done_total;
        } else {
            okChunks++;
        }
        if (mh) {
            CHAR* ln = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x100, 'dpML');
            if (ln) {
                CHAR* w = AppendFmt(ln, ln + 0x100, "0x%X 0x%X %lu %lu\n",
                                    done_total, st, (ULONG)got, chunk);
                ZwWriteFile(mh, NULL, NULL, NULL, &mio, ln, (ULONG)(w - ln), NULL, NULL);
                ExFreePoolWithTag(ln, 'dpML');
            }
        }
        if (!NT_SUCCESS(ZwWriteFile(h, NULL, NULL, NULL, &io, buf, chunk, NULL, NULL)))
            break;
        done_total += chunk;
    }
    if (mh) {
        CHAR* sum = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x200, 'dpMS');
        if (sum) {
            CHAR* w = AppendFmt(sum, sum + 0x200,
                "#summary wrote=0x%X ok=%lu bad=%lu firstBadOff=0x%X verdict=%s\n",
                done_total, okChunks, badChunks, firstBad,
                (badChunks == 0) ? "COMPLETE" : (okChunks ? "PARTIAL" : "FAILED"));
            ZwWriteFile(mh, NULL, NULL, NULL, &mio, sum, (ULONG)(w - sum), NULL, NULL);
            ExFreePoolWithTag(sum, 'dpMS');
        }
        ZwClose(mh);
    }
    ZwClose(h);
    return done_total;
}

static VOID DumpPass(PEPROCESS proc, PUCHAR buf, REG* regs, ULONG nreg, ULONG pass, PULONG writtenMb)
{
    ULONG i;
    for (i = 0; i < nreg; i++) {
        WCHAR path[128];
        SIZE_T done = 0;
        ULONG len = (ULONG)regs[i].Size;
        ULONG wrote;
        WCHAR tag = (pass == 1) ? L'1' : L'2';
        if (*writtenMb > 800) break;
        RtlStringCchPrintfW(path, RTL_NUMBER_OF(path), L"%ws%c%lu_%08llX.bin", OUT_DIR, tag, i, regs[i].Base);
        wrote = DumpRegionToFile(proc, regs[i].Base, len, buf, path);
        if (wrote == 0) { KF("[mdump] dump FAIL va=0x%llX len=0x%X\n", regs[i].Base, len); continue; }
        len = wrote;
        { CHAR line[160];
          RtlStringCchPrintfA(line, RTL_NUMBER_OF(line), "p%lu va=0x%llX size=0x%IX idx=%lu\n", pass, regs[i].Base, len, i);
          K(line); }
        *writtenMb += len / (1024*1024);
    }
    KF("[mdump] pass %lu done, total=%lu MB\n", pass, *writtenMb);
}

static VOID Run(PEPROCESS proc)
{
    REG* regs;
    PUCHAR buf;
    ULONG count = 0, n = 0;
    U64 addr = 0x10000;
    KAPC_STATE apc;
    ULONG writtenMb = 0;

    regs = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(REG) * MAX_REG, 'regS');
    buf  = ExAllocatePool2(POOL_FLAG_NON_PAGED, DUMP_CHUNK, 'dmpS');
    if (!regs || !buf) { if(regs) ExFreePoolWithTag(regs,'regS'); if(buf) ExFreePoolWithTag(buf,'dmpS'); return; }

    KeStackAttachProcess(proc, &apc);
    while (addr < 0x00007FFFFFFF0000ULL && count < MAX_REG) {
        MBINF m; SIZE_T r = 0;
        RtlZeroMemory(&m, sizeof(m));
        if (!NT_SUCCESS(ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)(ULONG_PTR)addr, 0, &m, sizeof(m), &r)) || !m.Size) {
            addr += 0x10000; continue;
        }
        if (m.State == 0x1000 && (m.Protect & 0xFF) == 0x04 && m.Type == 0x20000 &&
            m.Size >= 0x10000) {
            regs[count].Base = (U64)m.Base;
            regs[count].Size = m.Size;
            count++;
        }
        addr = (U64)m.Base + m.Size;
    }
    KeUnstackDetachProcess(&apc);
    KF("[mdump] regions=%lu\n", count);

    /* module .data / .rdata first: globals live here */
    {
        U64 base = 0, nt = 0;
        KAPC_STATE apc2;
        ULONG nsec, so, i;
        KeStackAttachProcess(proc, &apc2);
        base = 0;
        {   /* find the exe base via PEB */
            PPEB peb = (PPEB)PsGetProcessPeb(proc);
            if (peb) {
                PVOID ldr = *(PVOID*)((PUCHAR)peb + 0x18);
                if (ldr) {
                    LIST_ENTRY* head = (LIST_ENTRY*)((PUCHAR)ldr + 0x10);
                    LIST_ENTRY* cur;
                    UNICODE_STRING want;
                    RtlInitUnicodeString(&want, L"r5apex_dx12.exe");
                    for (cur = head->Flink; cur != head && cur; cur = cur->Flink) {
                        PUCHAR e = (PUCHAR)cur;
                        UNICODE_STRING bn;
                        bn.Length = *(USHORT*)(e + 0x58); bn.MaximumLength = bn.Length;
                        bn.Buffer = *(PWCH*)(e + 0x60);
                        if (bn.Buffer && bn.Length && RtlEqualUnicodeString(&bn, &want, TRUE)) {
                            base = *(U64*)(e + 0x30); break;
                        }
                    }
                }
            }
        }
        if (base) {
            U64 secs[8]; U64 secsz[8]; ULONG nsecs = 0;
            nt = base + *(ULONG*)(ULONG_PTR)(base + 0x3C);
            nsec = *(USHORT*)(ULONG_PTR)(nt + 6);
            so = *(USHORT*)(ULONG_PTR)(nt + 20);
            for (i = 0; i < nsec && nsecs < 8; i++) {
                PUCHAR sh = (PUCHAR)(nt + 24 + so + i * 40);
                ULONG vsize = *(ULONG*)(sh + 8), rva = *(ULONG*)(sh + 12);
                if ((sh[0] == '.' && sh[1] == 'd' && sh[2] == 'a' && sh[3] == 't') ||
                    (sh[0] == '.' && sh[1] == 'r' && sh[2] == 'd' && sh[3] == 'a')) {
                    secs[nsecs] = base + rva; secsz[nsecs] = vsize; nsecs++;
                }
            }
            KF("[mdump] module base=0x%llX sections=%lu\n", base, nsecs);
            for (i = 0; i < nsecs; i++) {
                ULONG len = (ULONG)min(secsz[i], (U64)REGION_CAP);
                ULONG wrote;
                WCHAR path[128];
                RtlStringCchPrintfW(path, RTL_NUMBER_OF(path), L"%wsm%lu_%08llX.bin", OUT_DIR, i, secs[i]);
                wrote = DumpRegionToFile(proc, secs[i], len, buf, path);
                if (wrote == 0) continue;
                len = wrote;
                { CHAR line[160];
                  RtlStringCchPrintfA(line, RTL_NUMBER_OF(line), "m va=0x%llX size=0x%IX idx=%lu\n", secs[i], len, i);
                  K(line); }
            }
        }
        KeUnstackDetachProcess(&apc2);
    }

    DumpPass(proc, buf, regs, count, 1, &writtenMb);
    K("[mdump] waiting 8s for user movement/rotation\n");
    SleepMs(8000);
    writtenMb = 0;
    DumpPass(proc, buf, regs, count, 2, &writtenMb);
    (void)n;

    ExFreePoolWithTag(regs, 'regS');
    ExFreePoolWithTag(buf, 'dmpS');
}

/* trigger loop: C:\ProgramData\sc_req.txt  ->  dump requested ranges -> sc_done.txt
   request lines:  "mod"  or  "0xVA 0xSIZE"   (up to 16 ranges)
*/
#define REQ_FILE  L"\\??\\C:\\ProgramData\\sc_req.txt"
#define DONE_FILE L"\\??\\C:\\ProgramData\\sc_done.txt"
#define ACK_FILE  L"\\??\\C:\\ProgramData\\sc_ack.txt"

static BOOLEAN FilePresent(PCWSTR path)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h; NTSTATUS st;
    RtlInitUnicodeString(&p, path);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&h, FILE_READ_ATTRIBUTES|SYNCHRONIZE, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) return FALSE;
    ZwClose(h);
    return TRUE;
}

/* read the request and delete it atomically (FILE_DELETE_ON_CLOSE) so the file
   never stays locked and a new request can always be written */
static NTSTATUS ReadAndDropRequest(PVOID buf, ULONG cap, PULONG outLen)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    FILE_STANDARD_INFORMATION fsi; LARGE_INTEGER off;

    RtlInitUnicodeString(&p, REQ_FILE);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, GENERIC_READ|DELETE|SYNCHRONIZE, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL,
                                 FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, FILE_OPEN,
                                 FILE_SYNCHRONOUS_IO_NONALERT|FILE_DELETE_ON_CLOSE, NULL, 0)))
        return STATUS_UNSUCCESSFUL;
    if (!NT_SUCCESS(ZwQueryInformationFile(h, &io, &fsi, sizeof(fsi), FileStandardInformation)) ||
        fsi.EndOfFile.QuadPart <= 0 || fsi.EndOfFile.QuadPart > cap) { ZwClose(h); return STATUS_INVALID_PARAMETER; }
    off.QuadPart = 0;
    if (!NT_SUCCESS(ZwReadFile(h, NULL, NULL, NULL, &io, buf, (ULONG)fsi.EndOfFile.QuadPart, &off, NULL))) {
        ZwClose(h); return STATUS_UNSUCCESSFUL;
    }
    ZwClose(h);   /* closes -> file deleted */
    *outLen = (ULONG)fsi.EndOfFile.QuadPart;
    return STATUS_SUCCESS;
}

static NTSTATUS ReadFileAllPath(PCWSTR path, PVOID buf, ULONG cap, PULONG outLen)
{
    UNICODE_STRING p; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h;
    FILE_STANDARD_INFORMATION fsi; LARGE_INTEGER off;
    RtlInitUnicodeString(&p, path);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, GENERIC_READ|SYNCHRONIZE, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL,
                                 FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
        return STATUS_UNSUCCESSFUL;
    if (!NT_SUCCESS(ZwQueryInformationFile(h, &io, &fsi, sizeof(fsi), FileStandardInformation)) ||
        fsi.EndOfFile.QuadPart <= 0 || fsi.EndOfFile.QuadPart > cap) { ZwClose(h); return STATUS_INVALID_PARAMETER; }
    off.QuadPart = 0;
    if (!NT_SUCCESS(ZwReadFile(h, NULL, NULL, NULL, &io, buf, (ULONG)fsi.EndOfFile.QuadPart, &off, NULL))) {
        ZwClose(h); return STATUS_UNSUCCESSFUL;
    }
    ZwClose(h);
    *outLen = (ULONG)fsi.EndOfFile.QuadPart;
    return STATUS_SUCCESS;
}

/* collect big RW private regions, biggest first (for value-based hunting) */
static ULONG CollectRegions(PEPROCESS proc, REG* out, ULONG max, U64 minSz, U64 maxSz)
{
    KAPC_STATE apc; U64 addr = 0x10000; ULONG n = 0, i, j;

    KeStackAttachProcess(proc, &apc);
    while (addr < 0x00007FFFFFFF0000ULL && n < max) {
        MBINF m; SIZE_T r = 0;
        RtlZeroMemory(&m, sizeof(m));
        if (!NT_SUCCESS(ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)(ULONG_PTR)addr, 0, &m, sizeof(m), &r)) || !m.Size) {
            addr += 0x10000; continue;
        }
        if (m.State == 0x1000 && (m.Protect & 0xFF) == 0x04 && m.Type == 0x20000 &&
            m.Size >= minSz && m.Size <= maxSz) {
            out[n].Base = (U64)m.Base;
            out[n].Size = m.Size;
            n++;
        }
        addr = (U64)m.Base + m.Size;
    }
    KeUnstackDetachProcess(&apc);

    /* biggest first */
    for (i = 0; i + 1 < n; i++)
        for (j = i + 1; j < n; j++)
            if (out[j].Size > out[i].Size) { REG t = out[i]; out[i] = out[j]; out[j] = t; }
    return n;
}

#define RVA_LOCAL_HANDLE 0x3D3DCD0ULL
#define RVA_ENTITY_ARRAY 0x6B515D8ULL
#define RVA_HIGHLIGHT_GLOBAL 0x72BE6C0ULL
/* npc_dummie ???????????????????????:
 *   ?? 0x7FF78F520000 ? ?? 0x7FF792609330  ? 0x30E9330
 *   ?? 0x7FF6ECD60000 ? ?? 0x7FF6EFE49330  ? 0x30E9330 */
#define RVA_VT_NPC_DUMMIE 0x30E9330ULL   /* ?????? */
#define RVA_VT_PLAYER     0x316930ULL    /* ??????????? +0x978? */
static U64 modBaseForNpc = 0;
static U64 g_vtExtra  = 0;  /* ??? 1??????? (RVA 0x30E9330) */
static U64 g_vtExtra2 = 0;  /* ??? 2???????? (RVA 0x316930) */
static ULONG g_vtManual = 0; /* vt2 ??????????? */
/* ---- ??????????????????????? ---- */
static ULONG g_autoGlow  = 1;    /* ???? */
/* ---- 整行高亮样式控制（依据 UC DX12 高亮帖） ---- */
#define GLOW_FLAG_TEAM_AGNOSTIC      0x00008000u
#define GLOW_FLAG_DISABLE_DEATH_FADE 0x00004000u
#define GLOW_VIS_ALWAYS              2u
#define GLOW_DEFAULT_FLAGS  (GLOW_FLAG_TEAM_AGNOSTIC | GLOW_FLAG_DISABLE_DEATH_FADE)
#define GLOW_DEFAULT_VIS    GLOW_VIS_ALWAYS
static ULONG g_autoFlags = GLOW_DEFAULT_FLAGS;
/* 实体侧 selector 偏移：不同 build 可能不同，运行时用 glowsel 切换
 * 依据 UC 帖子：渲染器读 selector；只写 contexts[0] 不写 selector 永远不渲染 */
static ULONG g_selOff  = 0x2A0;
static ULONG g_ctxOff  = 0x2A1;   /* contexts[0]，selector 后面一个字节 */
static ULONG g_focusOff= 0x2A8;
static ULONG g_parOff  = 0x2B4;
static ULONG g_fadeOff = 0x2AC;
static ULONG g_autoVis   = GLOW_DEFAULT_VIS;
static ULONG g_autoRow   = 50;   /* ?????????postProcess=1? */
static U64   g_glowCache[64];
static ULONG g_glowCacheN = 0;
/* ???????????? #39FF14 */
static float g_autoR = 0.22f;
static float g_autoG = 1.00f;
static float g_autoB = 0.08f;

/* one-shot closed loop for NPC hunting:
   read the entity array, pick N instances, dump them, sleep 2s, dump them again.
   the instance pointers never leave this call, so they cannot go stale between requests. */
static ULONG CollectInstances(PEPROCESS proc, U64 arrVa, U64* out, ULONG max, PUCHAR buf)
{
    ULONG cnt = 0;
    U64 off;
    for (off = 0; off < 0x200000 && cnt < max; off += 0x10000) {
        SIZE_T got = 0;
        ULONG k;
        RtlZeroMemory(buf, 0x10000);
        if (!NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(arrVa + off), PsGetCurrentProcess(),
                                            buf, 0x10000, KernelMode, &got)) || got != 0x10000)
            continue;
        for (k = 0; k + 8 <= 0x10000 && cnt < max; k += 0x20) {
            U64 v = *(U64*)(buf + k);
            ULONG idx = (ULONG)((off + k) / 0x20);
            if (v && idx > 100 && (v >> 47) == 0 && v >= 0x10000) out[cnt++] = v;
        }
    }
    return cnt;
}

static VOID DumpNpcPair(PEPROCESS proc, U64 modBase, PUCHAR buf, ULONG n)
{
    U64 insts[12];
    ULONG cnt, i, pass;
    WCHAR path[128];

    cnt = CollectInstances(proc, modBase + RVA_ENTITY_ARRAY, insts, 12, buf);
    KF("[mdump] npc: instances=%lu\n", cnt);
    if (!cnt) return;

    for (pass = 0; pass < 2; pass++) {
        for (i = 0; i < cnt; i++) {
            ULONG wrote;
            RtlStringCchPrintfW(path, RTL_NUMBER_OF(path), L"%wsn%lu_%lu_%llX.bin",
                                OUT_DIR, n, pass, insts[i]);
            wrote = DumpRegionToFile(proc, insts[i], 0x8000, buf, path);
            KF("[mdump] npc %lu inst=0x%llX wrote=0x%X\n", pass, insts[i], wrote);
        }
        if (pass == 0) { K("[mdump] npc: sleeping 2s\n"); SleepMs(2000); }
    }
}

/* "vd 0x<vtable>": scan entity instances, keep the ones whose vtable matches,
   and report their origin (+0x376C) plus dump a small window each. */
/* "p 0x<va>": report whether a read actually succeeds (vs. zeros written on failure) */
static VOID ProbeVa(PEPROCESS proc, U64 va, PUCHAR buf)
{
    SIZE_T got = 0;
    NTSTATUS st;
    RtlZeroMemory(buf, 0x40);
    st = MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)va, PsGetCurrentProcess(), buf, 0x40, KernelMode, &got);
    KF("[mdump] probe 0x%llX status=0x%08X got=%Iu first8=%02X %02X %02X %02X %02X %02X %02X %02X\n",
       va, st, got, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
}

static VOID DumpByVtable(PEPROCESS proc, U64 modBase, U64 wantVt, PUCHAR buf, ULONG n)
{
    U64 insts[256];
    ULONG cnt, i, hits = 0;

    cnt = CollectInstances(proc, modBase + RVA_ENTITY_ARRAY, insts, 256, buf);
    KF("[mdump] vd: instances=%lu wantVt=0x%llX\n", cnt, wantVt);

    for (i = 0; i < cnt; i++) {
        U64 vt = 0;
        float pos[3];
        if (!NT_SUCCESS(MemRead(proc, insts[i], &vt, 8))) continue;
        if (vt != wantVt) continue;
        hits++;
        RtlZeroMemory(pos, sizeof(pos));
        MemRead(proc, insts[i] + 0x376C, pos, 12);
        KF("[mdump] vd HIT inst=0x%llX pos=(%.1f, %.1f, %.1f)\n",
           insts[i], pos[0], pos[1], pos[2]);
        {   WCHAR path[128];
            RtlStringCchPrintfW(path, RTL_NUMBER_OF(path), L"%wsvd%lu_%llX.bin", OUT_DIR, n, insts[i]);
            DumpRegionToFile(proc, insts[i], 0x4000, buf, path);
        }
    }
    KF("[mdump] vd: hits=%lu\n", hits);
}


/* ================= player signature scan =================
   DT_BaseEntity ? health / teamNum / squadID / maxHealth ????????????
   +0x00 health(1..1000)  +0x10 team(0..4)  +0x1C squad(0..64)  +0x4C maxHealth
   ??????????????? vtable ????????
*/

/* ???? +0xDD0 ??????????bigdragon46 ???? OFF_BONES? */
static VOID DumpBones(PEPROCESS proc, U64 inst, PUCHAR buf)
{
    CHAR* txt = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x8000, 'bont');
    U64  p = 0;
    ULONG i;
    CHAR* w;
    if (!txt) return;
    RtlZeroMemory(txt, 0x8000); w = txt; w[0]=0;
    if (!NT_SUCCESS(MemRead(proc, inst + 0xDD0, &p, 8)) || !p || p < 0x10000 || (p >> 47)) {
        w = AppendFmt(w, txt + 0x8000, "no bone pointer at +0xDD0 (raw=0x%llX)\n", p);
        WriteFileAt(L"\\??\\C:\\ProgramData\\sc_bones.txt", txt, (ULONG)(w-txt)+1);
        ExFreePoolWithTag(txt,'bont'); return;
    }
    w = AppendFmt(w, txt + 0x8000, "bone array ptr = 0x%llX\n", p);
    {   ULONG n = 0x30 * 128;
        PUCHAR mb = ExAllocatePool2(POOL_FLAG_NON_PAGED, n, 'bont');
        if (mb) {
            SIZE_T got = 0;
            NTSTATUS st = MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)p, PsGetCurrentProcess(), mb, n, KernelMode, &got);
            w = AppendFmt(w, txt + 0x8000, "read status=0x%X got=%Iu\n", st, got);
            if (NT_SUCCESS(st)) {
                for (i = 0; i < 48; i++) {
                    float* m = (float*)(mb + i*0x30);
                    w = AppendFmt(w, txt + 0x8000, "[%02lu] %.2f %.2f %.2f %.2f | t=(%.1f,%.1f,%.1f)\n",
                                  i, m[0],m[1],m[2],m[3], m[3],m[7],m[11]);
                }
            }
            ExFreePoolWithTag(mb,'bont');
        }
    }
    WriteFileAt(L"\\??\\C:\\ProgramData\\sc_bones.txt", txt, (ULONG)(w-txt)+1);
    KF("[mdump] bones dumped ptr=0x%llX\n", p);
    ExFreePoolWithTag(txt,'bont');
}

static VOID SigScan(PEPROCESS proc, U64 arrVa, PUCHAR buf, ULONG reqId)
{
    CHAR* txt = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'sigt');
    PUCHAR eb  = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x2000, 'sigb');
    ULONG  off, hits = 0;
    CHAR*  w;
    if (!txt || !eb) { if(txt) ExFreePoolWithTag(txt,'sigt'); if(eb) ExFreePoolWithTag(eb,'sigb'); return; }
    RtlZeroMemory(txt, 0x10000); w = txt; w[0]=0;

    for (off = 0; off < 0x200000; off += 0x10000) {
        SIZE_T got = 0;
        ULONG k;
        if (!NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(arrVa + off), PsGetCurrentProcess(),
                                            buf, 0x10000, KernelMode, &got)) || got != 0x10000)
            continue;
        for (k = 0; k + 0x20 <= 0x10000; k += 0x20) {
            U64 inst = *(U64*)(buf + k);
            ULONG o;
            if (!inst || inst < 0x10000 || (inst >> 47)) continue;
            if (!NT_SUCCESS(MemRead(proc, inst, eb, 0x2000))) continue;
            for (o = 0x40; o + 0x100 < 0x2000; o += 4) {
                LONG h  = *(LONG*)(eb + o);
                LONG t  = *(LONG*)(eb + o + 0x10);
                LONG sq = *(LONG*)(eb + o + 0x1C);
                LONG mh = *(LONG*)(eb + o + 0x4C);
                float ps[3];
                if (h < 1 || h > 1000) continue;
                if (t < 0 || t > 4) continue;
                if (sq < 0 || sq > 64) continue;
                if (mh < 1 || mh > 2000) continue;
                RtlZeroMemory(ps, sizeof(ps));
                MemRead(proc, inst + 0x978, ps, 12);
                w = AppendFmt(w, txt + 0x10000, "0x%llX hOff=0x%X hp=%ld team=%ld squad=%ld maxhp=%ld pos=%.1f %.1f %.1f\n",
                              inst, o, h, t, sq, mh, ps[0], ps[1], ps[2]);
                hits++;
                break;
            }
            if (hits > 300) break;
        }
        if (hits > 300) break;
    }
    WriteFileAt(L"\\??\\C:\\ProgramData\\sc_players.txt", txt, (ULONG)(w - txt) + 1);
    KF("[mdump] sig done hits=%lu\n", hits);
    ExFreePoolWithTag(eb, 'sigb');
    ExFreePoolWithTag(txt, 'sigt');
}

static VOID WriteEntAddrList(void)
{
    CHAR* txt = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x4000, 'wltx');
    CHAR* w;
    ULONG i;
    if (!txt) return;
    RtlZeroMemory(txt, 0x4000);
    w = txt; w[0] = 0;
    for (i = 0; i < g_entAddrCount && i < 64; i++)
        w = AppendFmt(w, txt + 0x4000, "0x%llX\n", g_entAddr[i]);
    WriteFileAt(L"\\??\\C:\\ProgramData\\sc_addr.txt", txt, (ULONG)(w - txt) + 1);
    KF("[mdump] wl done count=%lu\n", g_entAddrCount);
    ExFreePoolWithTag(txt, 'wltx');
}

static VOID ClassPass(PEPROCESS proc, U64 arrVa, PUCHAR buf, U64 wantVt, BOOLEAN census);
static VOID SigScan(PEPROCESS proc, U64 arrVa, PUCHAR buf, ULONG reqId);
static VOID DumpBones(PEPROCESS proc, U64 inst, PUCHAR buf);
static NTSTATUS MemRead(PEPROCESS proc, U64 va, PVOID dst, SIZE_T len);
static NTSTATUS MemWrite(PEPROCESS proc, U64 va, PVOID src, SIZE_T len);
static VOID GlowTick(PEPROCESS proc);
static VOID GlowParity(PEPROCESS proc);
static VOID GlowColorRow(PEPROCESS proc, U64 globalVa, ULONG row, float r, float g, float b);
static BOOLEAN PrefixIs(const UCHAR* p, const UCHAR* end, const char* tag);
static float FabsF(float v);
static VOID GlowFields(PEPROCESS proc, U64 ent);
static VOID BoneScan(PEPROCESS proc, U64 ent);
static VOID BoneDump(PEPROCESS proc, U64 base, ULONG stride, ULONG idx);
static BOOLEAN BoneChainSig(PEPROCESS proc, U64 base, ULONG stride, float* headOut, float* originOut);
static BOOLEAN ParseUOpt(const UCHAR** pp, const UCHAR* end, ULONG* out);
static BOOLEAN GlowRowAddr(PEPROCESS proc, U64 globalVa, ULONG row, U64* entry);
static VOID GlowSetupRow(PEPROCESS proc, U64 globalVa, ULONG row,
                         float r, float g, float b, ULONG flags, ULONG vis);
static VOID GlowDumpRow(PEPROCESS proc, U64 globalVa, ULONG row);
static VOID GlowFindFree(PEPROCESS proc, U64 globalVa);
static VOID GlowCloneRow(PEPROCESS proc, U64 globalVa, ULONG src, ULONG dst);
static VOID HeapValueScan(PEPROCESS proc, float tx, float ty, float tz, float rad);
static BOOLEAN ReadEntPos(PEPROCESS proc, U64 inst, float* out);
static VOID LootScan(PEPROCESS proc, U64 arrVa);
static VOID ArrScan(PEPROCESS proc, ULONG stride, ULONG minCount);
static VOID WriteVa(PEPROCESS proc, UCHAR* p, UCHAR* le);

/* ---------------- glow keepalive (path 1: entity selector) ----------------
 * +0x294 selector / +0x295 contexts[0] / +0x29D focusedMask ? tick ??
 * +0x2A8 parity ???"????"???????? tick ??
 */
static U64   g_glowEnt = 0;
static ULONG g_glowRow = 0;
static ULONG g_glowOn  = 0;

static VOID GlowParity(PEPROCESS proc)
{
    ULONG pv;
    if (!g_glowEnt || !proc) return;
    /* ??? m_highlightFadeParity = 0x2B4??? 0x2A8? */
    if (NT_SUCCESS(MemRead(proc, g_glowEnt + 0x2B4, &pv, 4))) {
        pv ^= 1;
        MemWrite(proc, g_glowEnt + 0x2B4, &pv, 4);
    }
}

static VOID GlowTick(PEPROCESS proc)
{
    UCHAR b;
    if (!g_glowOn || !g_glowEnt || !proc) return;
    /* ???????????????????? [DT_HighlightSettings]?:
     *   m_highlightGenericContexts  0x2A0  (4 x uint8, ????? slot ????)
     *   m_highlightFocused          0x2A8  (uint32 ???, bit0 = slot0)
     *   m_highlightFadeDuration     0x2AC  (float, ??? 0 ??????)
     *   m_highlightFadeParity       0x2B4  (uint32 ????)
     */
    ULONG one = 1;
    float fd  = 1.0f;
    b = (UCHAR)(g_glowRow & 0xFF);
    MemWrite(proc, g_glowEnt + 0x2A0, &b, 1);      /* contexts[0] = ??? */
    MemWrite(proc, g_glowEnt + 0x2A8, &one, 4);    /* focused bit0 */
    MemWrite(proc, g_glowEnt + 0x2AC, &fd, 4);     /* fadeDuration = 1.0 */
}


/* hv <x> <y> <z> <radius> : ?? RW private ????????????????
 * ??????? sc_hits.txt????????? */
static float ParseF(const UCHAR** pp, const UCHAR* le)
{
    const UCHAR* q = *pp; float v = 0; BOOLEAN neg = FALSE; float frac = 0; int div = 1;
    while (q < le && *q == ' ') q++;
    if (q < le && *q == '-') { neg = TRUE; q++; }
    while (q < le && *q >= '0' && *q <= '9') { v = v * 10 + (*q - '0'); q++; }
    if (q < le && *q == '.') { q++; while (q < le && *q >= '0' && *q <= '9') { frac = frac*10 + (*q-'0'); div *= 10; q++; } }
    v += frac / div;
    *pp = q;
    return neg ? -v : v;
}

static VOID HeapValueScan(PEPROCESS proc, float tx, float ty, float tz, float rad)
{
    KAPC_STATE apc;
    U64 addr = 0x10000;
    ULONG hits = 0;
    PUCHAR buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x100000, 'hvSC');
    CHAR*  out = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x8000, 'hvOT');
    CHAR*  w;
    float r2 = rad * rad;
    if (!buf || !out) { if(buf) ExFreePoolWithTag(buf,'hvSC'); if(out) ExFreePoolWithTag(out,'hvOT'); return; }
    RtlZeroMemory(out, 0x8000); w = out;
    w = AppendFmt(w, out + 0x8000, "target=(%ld,%ld,%ld) r=%ld  [values x100]\n", (long)(tx*100),(long)(ty*100),(long)(tz*100),(long)(rad*100));

    while (addr < 0x00007FFFFFFF0000ULL && hits < 128) {
        MBINF m; SIZE_T rr = 0;
        U64 base, sz, off;
        RtlZeroMemory(&m, sizeof(m));
        KeStackAttachProcess(proc, &apc);
        if (!NT_SUCCESS(ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)(ULONG_PTR)addr, 0, &m, sizeof(m), &rr)) || !m.Size) {
            KeUnstackDetachProcess(&apc);
            addr += 0x10000; continue;
        }
        base = (U64)m.Base; sz = m.Size;
        KeUnstackDetachProcess(&apc);

        if (m.State == 0x1000 && (m.Protect & 0xFF) == 0x04 && m.Type == 0x20000 && sz >= 0x10000) {
            off = 0;
            while (off < sz && hits < 128) {
                SIZE_T got = 0;
                ULONG chunk = 0x100000;
                ULONG i;
                if (off + chunk > sz) chunk = (ULONG)(sz - off);
                if (chunk < 12) break;
                if (NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(base + off), PsGetCurrentProcess(),
                                                   buf, chunk, KernelMode, &got)) && got == chunk) {
                    for (i = 0; i + 12 <= chunk; i += 4) {
                        float* f = (float*)(buf + i);
                        float dx = f[0] - tx, dy = f[1] - ty, dz = f[2] - tz;
                        if (dx*dx + dy*dy + dz*dz < r2) {
                            w = AppendFmt(w, out + 0x8000, "0x%llX\n", base + off + i);
                            if (++hits >= 128) break;
                        }
                    }
                }
                off += chunk;
            }
        }
        if (sz) addr = base + sz; else addr += 0x10000;
    }
    WriteFileAt(L"\\??\\C:\\ProgramData\\sc_hits.txt", out, (ULONG)(w - out) + 1);
    ExFreePoolWithTag(buf, 'hvSC');
    ExFreePoolWithTag(out, 'hvOT');
    KF("[mdump] hv done hits=%lu\n", hits);
}


/* loot : ???????? m_iSignifierName(0x478, char*) ?????
 * ?? "prop_survival"???/???? "prop_death_box"?????
 * ???? + ??? sc_loot.txt??????? */
static VOID LootScan(PEPROCESS proc, U64 arrVa)
{
    PUCHAR buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'lotB');
    CHAR*  out = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x8000, 'lotO');
    CHAR*  w;
    ULONG off, n = 0;
    if (!buf || !out) { if(buf) ExFreePoolWithTag(buf,'lotB'); if(out) ExFreePoolWithTag(out,'lotO'); return; }
    RtlZeroMemory(out, 0x8000); w = out;
    w = AppendFmt(w, out + 0x8000, "# address sig pos(x,y,z)\n");

    for (off = 0; off < 0x200000 && n < 200; off += 0x10000) {
        SIZE_T got = 0;
        ULONG k;
        if (!NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(arrVa + off), PsGetCurrentProcess(),
                                            buf, 0x10000, KernelMode, &got)) || got != 0x10000)
            continue;
        for (k = 0; k + 0x20 <= 0x10000 && n < 200; k += 0x20) {
            U64 inst = *(U64*)(buf + k);
            U64 sp = 0;
            CHAR nm[32];
            if (!inst || inst < 0x10000 || (inst >> 47)) continue;
            if (!NT_SUCCESS(MemRead(proc, inst + 0x478, &sp, 8)) || !sp) continue;
            if (sp < 0x10000 || (sp >> 47)) continue;
            RtlZeroMemory(nm, sizeof(nm));
            if (!NT_SUCCESS(MemRead(proc, sp, nm, 31))) continue;
            if (!nm[0]) continue;
            if (!((nm[0]=='p') && (nm[1]=='r') && (nm[2]=='o') && (nm[3]=='p'))) continue;
            if (strncmp(nm, "prop_survival", 13) && strncmp(nm, "prop_death_box", 14)) continue;
            {
                float pv[3];
                if (!NT_SUCCESS(MemRead(proc, inst + 0x978, pv, 12))) {
                    pv[0] = pv[1] = pv[2] = 0.0f;
                }
                w = AppendFmt(w, out + 0x8000, "0x%llX %s %ld,%ld,%ld\n",
                              inst, nm, (long)(pv[0]*100),(long)(pv[1]*100),(long)(pv[2]*100));
                n++;
            }
        }
    }
    WriteFileAt(L"\\??\\C:\\ProgramData\\sc_loot.txt", out, (ULONG)(w - out) + 1);
    ExFreePoolWithTag(buf, 'lotB');
    ExFreePoolWithTag(out, 'lotO');
    KF("[mdump] loot done n=%lu\n", n);
}


/* glowcolor <row> <r> <g> <b>
 * ?? HighlightSettings ????? RGB?float?0..1?
 * row ?? = *(module + 0x72BE6C0) + row * 0x34
 *            +0x04 R, +0x08 G, +0x0C B
 */
static VOID GlowColorRow(PEPROCESS proc, U64 globalVa, ULONG row, float r, float g, float b)
{
    U64 tbl = 0, entry;
    if (!NT_SUCCESS(MemRead(proc, globalVa, &tbl, 8)) || !tbl) {
        K("[mdump] glowcolor: table ptr null\n");
        return;
    }
    entry = tbl + (U64)row * 0x34ULL;
    MemWrite(proc, entry + 0x04, &r, 4);
    MemWrite(proc, entry + 0x08, &g, 4);
    MemWrite(proc, entry + 0x0C, &b, 4);
    KF("[mdump] glowcolor row=%lu rgb=(%ld,%ld,%ld) entry=0x%llX [x100]\n", row, (long)(r*100),(long)(g*100),(long)(b*100), entry);
}


/* ---------------- arrscan: ?????? ----------------
 * ?????"?? N ????????????????????"???
 * ?????ItemManager ? ItemObject ???loot ???????
 *
 * arrscan <stride> <minCount>
 */
static BOOLEAN EntryHasWorldCoord(PUCHAR e, ULONG len)
{
    ULONG i;
    for (i = 0; i + 12 <= len; i += 4) {
        float* f = (float*)(e + i);
        float ax = f[0] < 0 ? -f[0] : f[0];
        float ay = f[1] < 0 ? -f[1] : f[1];
        float z  = f[2];
        if (ax > 100.0f && ax < 20000.0f &&
            ay < 20000.0f &&
            z  > -500.0f && z < 3000.0f)
            return TRUE;
    }
    return FALSE;
}

static VOID ArrScan(PEPROCESS proc, ULONG stride, ULONG minCount)
{
    PUCHAR buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x100000, 'arrB');
    CHAR*  out = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x4000, 'arrO');
    CHAR*  w;
    U64 addr = 0x10000;
    ULONG cands = 0;
    KAPC_STATE apc;

    if (!buf || !out) { if(buf) ExFreePoolWithTag(buf,'arrB'); if(out) ExFreePoolWithTag(out,'arrO'); return; }
    if (stride < 0x10 || stride > 0x200) stride = 0x40;
    if (minCount < 3) minCount = 8;

    RtlZeroMemory(out, 0x4000); w = out;
    w = AppendFmt(w, out + 0x4000, "# arrscan stride=0x%X minCount=%lu\n# base run entryCount hintOffset\n", stride, minCount);

    while (addr < 0x00007FFFFFFF0000ULL && cands < 40) {
        MBINF m; SIZE_T rr = 0;
        U64 base, sz, off;
        ULONG run = 0; U64 runBase = 0;
        ULONG lastHint = 0;
        RtlZeroMemory(&m, sizeof(m));
        KeStackAttachProcess(proc, &apc);
        if (!NT_SUCCESS(ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)(ULONG_PTR)addr, 0, &m, sizeof(m), &rr)) || !m.Size) {
            KeUnstackDetachProcess(&apc);
            addr += 0x10000; continue;
        }
        base = (U64)m.Base; sz = m.Size;
        KeUnstackDetachProcess(&apc);

        if (m.State == 0x1000 && (m.Protect & 0xFF) == 0x04 && m.Type == 0x20000 && sz >= 0x10000) {
            U64 limit = sz > 0x1000000ULL ? 0x1000000ULL : sz;   /* ?????? 16MB */
            off = 0;
            while (off + stride <= limit && cands < 40) {
                SIZE_T got = 0;
                ULONG chunk = 0x100000;
                ULONG k;
                if (off + chunk > limit) chunk = (ULONG)(limit - off);
                if (chunk < stride) break;
                if (NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(base + off), PsGetCurrentProcess(),
                                                   buf, chunk, KernelMode, &got)) && got == chunk) {
                    for (k = 0; k + stride <= chunk; k += stride) {
                        if (EntryHasWorldCoord(buf + k, stride)) {
                            if (run == 0) { runBase = base + off + k; lastHint = k; }
                            run++;
                        } else {
                            if (run >= minCount) {
                                w = AppendFmt(w, out + 0x4000, "0x%llX %lu %lu 0x0\n", runBase, run, run);
                                cands++;
                                if (cands >= 40) break;
                            }
                            run = 0;
                        }
                    }
                }
                if (cands >= 40) break;
                off += chunk;
            }
            if (run >= minCount && cands < 40) {
                w = AppendFmt(w, out + 0x4000, "0x%llX %lu %lu 0x0\n", runBase, run, run);
                cands++;
            }
        }
        if (sz) addr = base + sz; else addr += 0x10000;
    }
    WriteFileAt(L"\\??\\C:\\ProgramData\\sc_arr.txt", out, (ULONG)(w - out) + 1);
    ExFreePoolWithTag(buf, 'arrB');
    ExFreePoolWithTag(out, 'arrO');
    KF("[mdump] arrscan done stride=0x%X cands=%lu\n", stride, cands);
}

static VOID ServeRequests(PEPROCESS proc, U64* modData, ULONG* modSz, ULONG modN)
{
    PUCHAR buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, DUMP_CHUNK, 'snap');
    KF("[mdump] req buf=%p\n", buf);
    UCHAR* req = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x1000, 'reqS');
    ULONG n = 0;
    if (!buf || !req) { if(buf) ExFreePoolWithTag(buf,'snap'); if(req) ExFreePoolWithTag(req,'reqS'); return; }
    K("[mdump] serving requests\n");
    static ULONG hb = 0;

    for (;;) {
        /* sync target process each iteration (g_espProc changes on reattach) */
        if (g_espProc && g_espProc != proc) { proc = g_espProc; KF("[mdump] req proc sync 0x%llX\n", (U64)(ULONG_PTR)proc); }
        if (!TGT_ALIVE()) { SleepMs(500); continue; }
        if (FilePresent(REQ_FILE)) {
            ULONG len = 0;
            ULONG k;
            K("[mdump] req: got request\n");
            if (NT_SUCCESS(ReadAndDropRequest(req, 0x0FF0, &len))) {
                KF("[mdump] req: len=%lu\n", len);
                UCHAR* p = req; UCHAR* end = req + len;
                n++;
                while (p < end) {
                    UCHAR* le = p;
                    while (le < end && *le != '\r' && *le != '\n') le++;
                    if (le > p) {
                        if ((p[0] == 'g' || p[0] == 'G') && (p[1] == 'l' || p[1] == 'L') && (p[2] == 'o' || p[2] == 'O') && (p[3] == 'w' || p[3] == 'W') && (p[4] == 'a' || p[4] == 'A')) {
                            const UCHAR* qg = p + 5;
                            ULONG on = 0, rw = 0; BOOLEAN s1 = FALSE, s2 = FALSE;
                            while (qg < le && *qg == ' ') qg++;
                            while (qg < le) { UCHAR c = *qg;
                                if (c >= '0' && c <= '9') { on = on * 10 + (c - '0'); s1 = TRUE; }
                                else break; qg++; }
                            while (qg < le && *qg == ' ') qg++;
                            while (qg < le) { UCHAR c = *qg;
                                if (c >= '0' && c <= '9') { rw = rw * 10 + (c - '0'); s2 = TRUE; }
                                else break; qg++; }
                            if (s1) { g_autoGlow = on ? 1 : 0; g_glowCacheN = 0; }
                            if (s2 && rw < 256) { g_autoRow = rw; g_glowCacheN = 0; }
                            {
                                float cr = ParseF(&qg, le), cg = ParseF(&qg, le), cb = ParseF(&qg, le);
                                if (cr >= 0.0f && cg >= 0.0f && cb >= 0.0f) {
                                    g_autoR = cr; g_autoG = cg; g_autoB = cb;
                                }
                            }
                            KF("[mdump] glowauto on=%lu row=%lu rgb=(%ld,%ld,%ld) [x100]\n",
                               g_autoGlow, g_autoRow,
                               (long)(g_autoR*100),(long)(g_autoG*100),(long)(g_autoB*100));
                        }
                        else if ((p[0] == 'v' || p[0] == 'V') && (p[1] == 't' || p[1] == 'T') && p[2] == '2') {
                            const UCHAR* qv = p + 3;
                            U64 vv = 0; BOOLEAN sv = FALSE;
                            while (qv < le && *qv == ' ') qv++;
                            if (qv + 1 < le && qv[0] == '0' && (qv[1] == 'x' || qv[1] == 'X')) {
                                qv += 2;
                                while (qv < le) { UCHAR c = *qv; ULONG d;
                                    if (c >= '0' && c <= '9') d = c - '0';
                                    else if ((c|0x20) >= 'a' && (c|0x20) <= 'f') d = (c|0x20) - 'a' + 10;
                                    else break; vv = vv * 16 + d; qv++; sv = TRUE; }
                            }
                            if (sv) { g_vtExtra = vv; g_vtExtra2 = 0; g_vtManual = 1; KF("[mdump] vt2 set 0x%llX (manual)\n", vv); }
                            else K("[mdump] vt2: bad args\n");
                        }
                        else if ((p[0] == 'a' || p[0] == 'A') && (p[1] == 'r' || p[1] == 'R') && (p[2] == 'r' || p[2] == 'R')) {
                            const UCHAR* qa = p + 7;   /* "arrscan" = 7 chars */
                            ULONG st = 0, mn = 0; BOOLEAN s1 = FALSE, s2 = FALSE;
                            while (qa < le && *qa == ' ') qa++;
                            if (qa + 1 < le && qa[0] == '0' && (qa[1] == 'x' || qa[1] == 'X')) {
                                qa += 2;
                                while (qa < le) { UCHAR c = *qa; ULONG d;
                                    if (c >= '0' && c <= '9') d = c - '0';
                                    else if ((c|0x20) >= 'a' && (c|0x20) <= 'f') d = (c|0x20) - 'a' + 10;
                                    else break; st = st * 16 + d; qa++; s1 = TRUE; }
                            } else {
                                while (qa < le) { UCHAR c = *qa;
                                    if (c >= '0' && c <= '9') { st = st * 10 + (c - '0'); s1 = TRUE; }
                                    else break; qa++; }
                            }
                            while (qa < le && *qa == ' ') qa++;
                            while (qa < le) { UCHAR c = *qa;
                                if (c >= '0' && c <= '9') { mn = mn * 10 + (c - '0'); s2 = TRUE; }
                                else break; qa++; }
                            if (s1) {
                                KF("[mdump] arrscan start stride=0x%X min=%lu\n", st, mn ? mn : 8);
                                ArrScan(proc, st, mn ? mn : 8);
                            } else K("[mdump] arrscan: bad args\n");
                        }


                        else if (PrefixIs(p, le, "bonescan")) {
                            const UCHAR* qb = p + 8;
                            U64 ev = 0; BOOLEAN got = FALSE;
                            while (qb < le && *qb == ' ') qb++;
                            if (qb + 1 < le && qb[0] == '0' && (qb[1] == 'x' || qb[1] == 'X')) qb += 2;
                            while (qb < le) { UCHAR c = *qb; U64 d;
                                if (c >= '0' && c <= '9') d = c - '0';
                                else if ((c|0x20) >= 'a' && (c|0x20) <= 'f') d = (c|0x20) - 'a' + 10;
                                else break; ev = ev * 16 + d; qb++; got = TRUE; }
                            if (got) { KF("[mdump] bonescan start ent=0x%llX\n", ev); BoneScan(proc, ev); }
                            else K("[mdump] bonescan: usage bonescan 0x<entity>\n");
                        }
                        else if (PrefixIs(p, le, "bonedump")) {
                            const UCHAR* qb = p + 8;
                            U64 bv = 0; ULONG sd = 0x30, ix = 0;
                            while (qb < le && *qb == ' ') qb++;
                            if (qb + 1 < le && qb[0] == '0' && (qb[1] == 'x' || qb[1] == 'X')) qb += 2;
                            while (qb < le) { UCHAR c = *qb; U64 d;
                                if (c >= '0' && c <= '9') d = c - '0';
                                else if ((c|0x20) >= 'a' && (c|0x20) <= 'f') d = (c|0x20) - 'a' + 10;
                                else break; bv = bv * 16 + d; qb++; }
                            if (bv) {
                                ULONG t;
                                if (ParseUOpt(&qb, le, &t)) { sd = t; if (ParseUOpt(&qb, le, &ix)) { } }
                                if (sd != 0x30 && sd != 0x40) sd = 0x30;
                                BoneDump(proc, bv, sd, ix);
                            } else K("[mdump] bonedump: usage bonedump 0x<addr> [stride] [idx]\n");
                        }

                        else if (PrefixIs(p, le, "glowfields")) {
                            const UCHAR* qg = p + 10;
                            U64 ev = 0; BOOLEAN got = FALSE;
                            while (qg < le && *qg == ' ') qg++;
                            if (qg + 1 < le && qg[0] == '0' && (qg[1] == 'x' || qg[1] == 'X')) qg += 2;
                            while (qg < le) { UCHAR c = *qg; U64 d;
                                if (c >= '0' && c <= '9') d = c - '0';
                                else if ((c|0x20) >= 'a' && (c|0x20) <= 'f') d = (c|0x20) - 'a' + 10;
                                else break; ev = ev * 16 + d; qg++; got = TRUE; }
                            if (got) GlowFields(proc, ev);
                            else K("[mdump] glowfields: usage glowfields 0x<entity>\n");
                        }
                        else if (PrefixIs(p, le, "glowsel")) {
                            const UCHAR* qg = p + 7;
                            ULONG v = 0;
                            if (ParseUOpt(&qg, le, &v) && v < 0x400) {
                                g_selOff = v;
                                KF("[mdump] glowsel=0x%X ctx=0x%X\n", g_selOff, g_ctxOff);
                            } else K("[mdump] glowsel: usage glowsel <hexoffset>\n");
                        }
                        else if (PrefixIs(p, le, "glowfind")) {
                            GlowFindFree(proc, modBaseForNpc + RVA_HIGHLIGHT_GLOBAL);
                        }
                        else if (PrefixIs(p, le, "glowdump")) {
                            const UCHAR* qd = p + 8;
                            ULONG rw = 0;
                            if (ParseUOpt(&qd, le, &rw))
                                GlowDumpRow(proc, modBaseForNpc + RVA_HIGHLIGHT_GLOBAL, rw);
                            else K("[mdump] glowdump: bad args\n");
                        }
                        else if (PrefixIs(p, le, "glowclone")) {
                            const UCHAR* qq = p + 9;
                            ULONG a = 0, b2 = 0;
                            if (ParseUOpt(&qq, le, &a) && ParseUOpt(&qq, le, &b2))
                                GlowCloneRow(proc, modBaseForNpc + RVA_HIGHLIGHT_GLOBAL, a, b2);
                            else K("[mdump] glowclone: usage glowclone <src> <dst>\n");
                        }
                        else if (PrefixIs(p, le, "glowrow")) {
                            const UCHAR* qr = p + 7;
                            ULONG rw = 0, fl = 0, vs = 0;
                            float cr = 0.22f, cg2 = 1.0f, cb2 = 0.08f;
                            if (ParseUOpt(&qr, le, &rw)) {
                                float a1 = ParseF(&qr, le), a2 = ParseF(&qr, le), a3 = ParseF(&qr, le);
                                if (a1 == a1 && a2 == a2 && a3 == a3 && (a1 + a2 + a3) > 0.0f) {
                                    cr = a1; cg2 = a2; cb2 = a3;
                                }
                                if (!ParseUOpt(&qr, le, &fl)) fl = g_autoFlags;
                                if (!ParseUOpt(&qr, le, &vs)) vs = g_autoVis;
                                GlowSetupRow(proc, modBaseForNpc + RVA_HIGHLIGHT_GLOBAL,
                                             rw, cr, cg2, cb2, fl, vs);
                            } else K("[mdump] glowrow: usage glowrow <row> [r g b] [flags] [vis]\n");
                        }
                        else if ((p[0] == 'g' || p[0] == 'G') && (p[1] == 'l' || p[1] == 'L') && (p[2] == 'o' || p[2] == 'O') && (p[3] == 'w' || p[3] == 'W') && (p[4] == 'c' || p[4] == 'C')) {
                            const UCHAR* qc = p + 5;
                            ULONG row = 0; BOOLEAN seen = FALSE;
                            while (qc < le) { UCHAR c = *qc;
                                if (c >= '0' && c <= '9') { row = row * 10 + (c - '0'); seen = TRUE; }
                                else if (seen) break;
                                qc++; }
                            if (seen) {
                                float cr = ParseF(&qc, le), cg = ParseF(&qc, le), cb = ParseF(&qc, le);
                                GlowColorRow(proc, modBaseForNpc + RVA_HIGHLIGHT_GLOBAL, row, cr, cg, cb);
                            } else K("[mdump] glowcolor: bad args\n");
                        }
                        else if ((p[0] == 'l' || p[0] == 'L') && (p[1] == 'o' || p[1] == 'O') && (p[2] == 'o' || p[2] == 'O') && (p[3] == 't' || p[3] == 'T')) {
                            K("[mdump] loot scan start\n");
                            LootScan(proc, modBaseForNpc + RVA_ENTITY_ARRAY);
                        }
                        else if ((p[0] == 'h' || p[0] == 'H') && (p[1] == 'v' || p[1] == 'V') && p[2] == ' ') {
                            const UCHAR* qf = p + 3;
                            float fx = ParseF(&qf, le), fy = ParseF(&qf, le), fz = ParseF(&qf, le), fr = ParseF(&qf, le);
                            if (fr <= 0) fr = 100.0f;
                            KF("[mdump] hv start (%ld,%ld,%ld) r=%ld [x100]\n", (long)(fx*100),(long)(fy*100),(long)(fz*100),(long)(fr*100));
                            HeapValueScan(proc, fx, fy, fz, fr);
                        }
                        else if ((p[0] == 'g' || p[0] == 'G') && (p[1] == 'l' || p[1] == 'L') && (p[2] == 'o' || p[2] == 'O')) {
                            UCHAR* q4 = p;
                            if ((q4[3] == 'w' || q4[3] == 'W') && (q4[4] == 'o' || q4[4] == 'O')) {
                                GlowParity(proc);
                                g_glowOn = 0; g_glowEnt = 0;
                                K("[mdump] glowoff\n");
                            } else {
                                U64 gva = 0; ULONG grow = 0; UCHAR* q5 = p + 4;
                                while (q5 < le && *q5 != ' ') q5++;
                                while (q5 < le && *q5 == ' ') q5++;
                                if (q5 + 1 < le && q5[0] == '0' && (q5[1] == 'x' || q5[1] == 'X')) q5 += 2;
                                while (q5 < le) { UCHAR c = *q5; U64 d;
                                    if (c >= '0' && c <= '9') d = c - '0';
                                    else if ((c|0x20) >= 'a' && (c|0x20) <= 'f') d = (c|0x20) - 'a' + 10;
                                    else break; gva = gva * 16 + d; q5++; }
                                while (q5 < le && *q5 == ' ') q5++;
                                while (q5 < le) { UCHAR c = *q5; ULONG d;
                                    if (c >= '0' && c <= '9') d = c - '0';
                                    else break; grow = grow * 10 + d; q5++; }
                                if (gva) {
                                    g_glowEnt = gva; g_glowRow = grow & 0xFF; g_glowOn = 1;
                                    GlowParity(proc);            /* ?????????? */
                                    KF("[mdump] glow on ent=0x%llX row=%lu\n", gva, g_glowRow);
                                } else {
                                    K("[mdump] glow: bad args\n");
                                }
                            }
                        }
                        else if ((p[0] == 'm' || p[0] == 'M') && (p[1] == 'o' || p[1] == 'O') && (p[2] == 'd' || p[2] == 'D')) {
                            UCHAR* q3 = p + 4;
                            ULONG nv = 0, seen = 0;
                            while (q3 < le) {
                                if (*q3 >= '0' && *q3 <= '9') { nv = nv * 10 + (*q3 - '0'); seen = 1; }
                                else if (seen) break;
                                q3++;
                            }
                            if (seen) { g_espMode = (nv == 0) ? 0 : 1; }
                            KF("[mdump] mode=%lu (0=players 1=all)\n", g_espMode);
                        }
                        else if ((p[0] == 'w' || p[0] == 'W') && (p[1] == 'l' || p[1] == 'L')) {
                            WriteEntAddrList();
                        }
                        else if ((p[0] == 'w' || p[0] == 'W') && p[1] == ' ') {
                            WriteVa(proc, p, le);
                        }
                        else if ((p[0] == 'p' || p[0] == 'P') && p[1] == ' ') {
                            U64 va2 = 0;
                            UCHAR* q2 = p + 2;
                            while (q2 < le && *q2 == ' ') q2++;
                            if (q2 + 1 < le && q2[0] == '0' && (q2[1] == 'x' || q2[1] == 'X')) q2 += 2;
                            while (q2 < le) {
                                UCHAR c = *q2; U64 d;
                                if (c >= '0' && c <= '9') d = c - '0';
                                else if ((c | 0x20) >= 'a' && (c | 0x20) <= 'f') d = (c | 0x20) - 'a' + 10;
                                else break;
                                va2 = va2 * 16 + d; q2++;
                            }
                            if (va2) ProbeVa(proc, va2, buf);
                        }
                        else if ((p[0] == 'b' || p[0] == 'B') && (p[1] == 'o' || p[1] == 'O')) {
                            U64 bi = 0; UCHAR* q4 = p;
                            while (q4 < le && *q4 != ' ') q4++;
                            while (q4 < le && *q4 == ' ') q4++;
                            if (q4 + 1 < le && q4[0]=='0' && (q4[1]=='x'||q4[1]=='X')) q4 += 2;
                            while (q4 < le) { UCHAR c=*q4; U64 d;
                                if (c>='0'&&c<='9') d=c-'0';
                                else if ((c|0x20)>='a'&&(c|0x20)<='f') d=(c|0x20)-'a'+10;
                                else break; bi=bi*16+d; q4++; }
                            if (bi) DumpBones(proc, bi, buf);
                        }
                        else if ((p[0] == 's' || p[0] == 'S') && (p[1] == 'i' || p[1] == 'I')) {
                            SigScan(proc, modBaseForNpc + RVA_ENTITY_ARRAY, buf, n);
                        }
                        else if ((p[0] == 'c' || p[0] == 'C') && (p[1] == 'l' || p[1] == 'L')) {
                            ClassPass(proc, modBaseForNpc + RVA_ENTITY_ARRAY, buf, 0, TRUE);
                        }
                        else if ((p[0] == 'e' || p[0] == 'E') && (p[1] == 'n' || p[1] == 'N')) {
                            U64 want2 = 0;
                            UCHAR* q3 = p;
                            while (q3 < le && *q3 != ' ') q3++;
                            while (q3 < le && *q3 == ' ') q3++;
                            if (q3 + 1 < le && q3[0] == '0' && (q3[1] == 'x' || q3[1] == 'X')) q3 += 2;
                            while (q3 < le) {
                                UCHAR c = *q3; U64 d;
                                if (c >= '0' && c <= '9') d = c - '0';
                                else if ((c | 0x20) >= 'a' && (c | 0x20) <= 'f') d = (c | 0x20) - 'a' + 10;
                                else break;
                                want2 = want2 * 16 + d; q3++;
                            }
                            KF("[mdump] ent req vt=0x%llX\n", want2);
                            if (want2) ClassPass(proc, modBaseForNpc + RVA_ENTITY_ARRAY, buf, want2, FALSE);
                        }
                        else if (p[0] == 'v' && (p[1] == 'd' || p[1] == 'D')) {
                            U64 want = 0;
                            UCHAR* q = p + 2;
                            while (q < le && *q == ' ') q++;
                            if (q + 1 < le && q[0] == '0' && (q[1] == 'x' || q[1] == 'X')) q += 2;
                            while (q < le) {
                                UCHAR c = *q; U64 d;
                                if (c >= '0' && c <= '9') d = c - '0';
                                else if ((c | 0x20) >= 'a' && (c | 0x20) <= 'f') d = (c | 0x20) - 'a' + 10;
                                else break;
                                want = want * 16 + d; q++;
                            }
                            if (want) DumpByVtable(proc, modBaseForNpc, want, buf, n);
                        }
                        else if (p[0] == 'n' || p[0] == 'N') {
                            DumpNpcPair(proc, modBaseForNpc, buf, n);
                        }
                        else if (p[0] == 'h' || p[0] == 'H') {
                            REG* hr = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(REG) * 256, 'hreg');
                            if (hr) {
                                ULONG hn = CollectRegions(proc, hr, 256, 0x00100000, 0x04000000ULL), hi, mb = 0;
                                KF("[mdump] snap %lu heap regions=%lu\n", n, hn);
                                for (hi = 0; hi < hn && mb < 300; hi++) {
                                    WCHAR path[128];
                                    ULONG wrote;
                                    RtlStringCchPrintfW(path, RTL_NUMBER_OF(path), L"%ws%lu_h%lu_%llX.bin",
                                                        OUT_DIR, n, hi, hr[hi].Base);
                                    wrote = DumpRegionToFile(proc, hr[hi].Base, (ULONG)hr[hi].Size, buf, path);
                                    if (wrote) {
                                        mb += wrote / (1024*1024);
                                        KF("[mdump] snap %lu heap %lu va=0x%llX size=0x%X\n",
                                           n, hi, hr[hi].Base, wrote);
                                    }
                                }
                                KF("[mdump] snap %lu heap total=%lu MB\n", n, mb);
                                ExFreePoolWithTag(hr, 'hreg');
                            }
                        }
                        else if (p[0] == 's' || p[0] == 'S') {
                            REG* sr = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(REG) * 4096, 'sreg');
                            if (sr) {
                                ULONG sn = CollectRegions(proc, sr, 4096, 0x1000, 0x00100000), si, mb = 0;
                                KF("[mdump] snap %lu small regions=%lu\n", n, sn);
                                for (si = 0; si < sn && mb < 300; si++) {
                                    WCHAR path[128];
                                    ULONG wrote;
                                    RtlStringCchPrintfW(path, RTL_NUMBER_OF(path), L"%ws%lu_s%lu_%llX.bin",
                                                        OUT_DIR, n, si, sr[si].Base);
                                    wrote = DumpRegionToFile(proc, sr[si].Base, (ULONG)sr[si].Size, buf, path);
                                    if (wrote) mb += wrote / (1024*1024);
                                }
                                KF("[mdump] snap %lu small total=%lu MB regions=%lu\n", n, mb, sn);
                                ExFreePoolWithTag(sr, 'sreg');
                            }
                        }
                        else if (p[0] == 'm' || p[0] == 'M') {
                            for (k = 0; k < modN; k++) {
                                WCHAR path[128];
                                RtlStringCchPrintfW(path, RTL_NUMBER_OF(path), L"%ws%lu_mod%lu.bin", OUT_DIR, n, k);
                                if (DumpRegionToFile(proc, modData[k], modSz[k], buf, path))
                                    KF("[mdump] snap %lu mod%lu va=0x%llX\n", n, k, modData[k]);
                            }
                        } else if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
                            U64 va = 0; U64 sz = 0; ULONG wrote2 = 0;
                            p += 2;
                            while (p < le) { UCHAR c = *p; U64 d;
                                if (c >= '0' && c <= '9') d = c - '0';
                                else if ((c|0x20) >= 'a' && (c|0x20) <= 'f') d = (c|0x20) - 'a' + 10;
                                else break;
                                va = va * 16 + d; p++; }
                            while (p < le && *p == ' ') p++;
                            if (p + 1 < le && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
                            while (p < le) { UCHAR c = *p; U64 d;
                                if (c >= '0' && c <= '9') d = c - '0';
                                else if ((c|0x20) >= 'a' && (c|0x20) <= 'f') d = (c|0x20) - 'a' + 10;
                                else break;
                                sz = sz * 16 + d; p++; }
                            if (va && sz) {
                                WCHAR path[128];
                                RtlStringCchPrintfW(path, RTL_NUMBER_OF(path), L"%ws%lu_%llX.bin", OUT_DIR, n, va);
                                wrote2 = DumpRegionToFile(proc, va, (ULONG)sz, buf, path);
                                if (wrote2 == 0) KF("[mdump] req FAIL va=0x%llX size=0x%llX\n", va, sz);
                                if (wrote2)
                                    KF("[mdump] snap %lu va=0x%llX size=0x%llX\n", n, va, sz);
                            }
                        }
                    }
                    p = le;
                    while (p < end && (*p == '\r' || *p == '\n')) p++;
                }
                {   CHAR ack[256];
                    RtlStringCchPrintfA(ack, RTL_NUMBER_OF(ack),
                                        "id=%lu lines=%lu status=done\n", n, n);
                    WA(ACK_FILE, ack, (ULONG)strlen(ack));
                    KF("[mdump] req %lu done\n", n);
                }
            } else {
                K("[mdump] req: read/deleted failed\n");
            }
        }
        SleepMs(100);
        if ((++hb % 600) == 0) K("[mdump] req loop alive\n");
    }
}

/* ---------- ESP: publish camera/player state to a feed file every 16ms ---------- */
#define FEED_FILE L"\\??\\C:\\ProgramData\\sc_feed.bin"

typedef struct _EINFO {
    ULONG Hp;
    ULONG HpMax;
    ULONG Sh;
    ULONG ShMax;
    UCHAR Team;
    UCHAR Life;
    UCHAR NameLen;
    UCHAR Flags;
    CHAR  Name[20];
} EINFO;   /* 36 ?? */

typedef struct _FEED {
    ULONG Magic;        /* 'FEED' */
    ULONG Version;      /* 4 */
    float Cam[3];
    float Ang[3];
    float Pos[3];
    ULONG Count;        /* players of the same class */
    ULONG Ok;
    U64   Inst;
    float Ent[FEED_MAX_ENT][3];
    EINFO Info[FEED_MAX_ENT];
} FEED;

#define ENT_STRIDE       0x20ULL
#define OFF_CAMERA       0x1F78ULL
#define OFF_ANGLES       0x1F84ULL
#define OFF_ORIGIN       0x376CULL

int _fltused = 0;
NTSYSAPI NTSTATUS NTAPI PsGetProcessExitStatus(PEPROCESS Process);
static NTSTATUS MemRead(PEPROCESS proc, U64 va, PVOID dst, SIZE_T len);

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

static ULONG HexNib(UCHAR c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if ((c | 0x20) >= 'a' && (c | 0x20) <= 'f') return (c | 0x20) - 'a' + 10;
    return 0xFF;
}

/* w 0x<va> <hexbytes>   e.g.  w 0x1234ABCD 0102FF  */
static VOID WriteVa(PEPROCESS proc, UCHAR* p, UCHAR* le)
{
    U64 va = 0;
    UCHAR* q = p;
    UCHAR bytes[64];
    ULONG  n = 0, hi, lo;
    NTSTATUS st;

    while (q < le && *q != ' ') q++;
    while (q < le && *q == ' ') q++;
    if (q + 1 < le && q[0] == '0' && (q[1] == 'x' || q[1] == 'X')) q += 2;
    while (q < le) {
        UCHAR c = *q; U64 d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if ((c | 0x20) >= 'a' && (c | 0x20) <= 'f') d = (c | 0x20) - 'a' + 10;
        else break;
        va = va * 16 + d; q++;
    }
    while (q < le && *q == ' ') q++;
    while (q < le && n < sizeof(bytes)) {
        hi = HexNib(*q); if (hi == 0xFF) break;
        lo = (q + 1 < le) ? HexNib(q[1]) : 0xFF; if (lo == 0xFF) break;
        bytes[n++] = (UCHAR)((hi << 4) | lo);
        q += 2;
    }
    if (!va || !n) { K("[mdump] w: bad args\n"); return; }
    st = MemWrite(proc, va, bytes, n);
    KF("[mdump] w 0x%llX len=%lu status=0x%X\n", va, n, st);
}

static ULONG StartsWithStr(const char* hay, const char* needle)
{
    return hay && needle && strncmp(hay, needle, strlen(needle)) == 0;
}
static ULONG ContainsStr(const char* hay, const char* needle)
{
    return hay && needle && strstr(hay, needle) != NULL;
}

/* collect instances whose vtable equals the local player's (other C_Player) */
/* Scan all instances for a plausible world position at entity+0x978 */

/* ================= batch class tooling ================= */
#define CLS_MAX 512
typedef struct _CLSREC { U64 Vt; ULONG Count; U64 Sample[3]; } CLSREC;

static CHAR* AppendFmt(CHAR* p, CHAR* end, const CHAR* fmt, ...)
{
    CHAR tmp[256];
    va_list ap;
    size_t n = 0;
    va_start(ap, fmt);
    RtlStringCchVPrintfA(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    RtlStringCchLengthA(tmp, sizeof(tmp), &n);
    if (p + n < end) { RtlCopyMemory(p, tmp, n); p += n; *p = 0; }
    return p;
}

/* ?????????? vtable ???cls ?????ent ??????? + ?? */
static VOID ClassPass(PEPROCESS proc, U64 arrVa, PUCHAR buf, U64 wantVt, BOOLEAN census)
{
    CLSREC* rec = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CLSREC) * CLS_MAX, 'clsr');
    CHAR*    txt = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'clst');
    ULONG    ncls = 0, off;
    CHAR*    w;

    if (!rec || !txt) { if (rec) ExFreePoolWithTag(rec,'clsr'); if (txt) ExFreePoolWithTag(txt,'clst'); return; }
    RtlZeroMemory(rec, sizeof(CLSREC) * CLS_MAX);
    RtlZeroMemory(txt, 0x10000);
    w = txt; w[0] = 0;

    for (off = 0; off < 0x200000; off += 0x10000) {
        SIZE_T got = 0;
        ULONG k;
        if (!NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(arrVa + off), PsGetCurrentProcess(),
                                            buf, 0x10000, KernelMode, &got)) || got != 0x10000)
            continue;
        for (k = 0; k + 0x20 <= 0x10000; k += 0x20) {
            U64 inst = *(U64*)(buf + k);
            U64 vt = 0;
            if (!inst || inst < 0x10000 || (inst >> 47)) continue;
            if (!NT_SUCCESS(MemRead(proc, inst, &vt, 8)) || !vt) continue;

            if (!census) {
                float v[3];
                if (vt != wantVt) continue;
                RtlZeroMemory(v, sizeof(v));
                MemRead(proc, inst + 0x978, v, 12);
                w = AppendFmt(w, txt + 0x10000, "0x%llX 0x%llX %.2f %.2f %.2f\n",
                              inst, vt, v[0], v[1], v[2]);
                continue;
            }
            {   ULONG i;
                for (i = 0; i < ncls; i++) if (rec[i].Vt == vt) break;
                if (i == ncls) {
                    if (ncls >= CLS_MAX) continue;
                    rec[ncls].Vt = vt; rec[ncls].Count = 0;
                    ncls++;
                }
                if (rec[i].Count < 3) rec[i].Sample[rec[i].Count] = inst;
                rec[i].Count++;
            }
        }
    }

    if (census) {
        ULONG i, j;
        for (i = 0; i < ncls; i++)
            for (j = i + 1; j < ncls; j++)
                if (rec[j].Count > rec[i].Count) { CLSREC t = rec[i]; rec[i] = rec[j]; rec[j] = t; }
        w = AppendFmt(w, txt + 0x10000, "# classes=%lu\n", ncls);
        for (i = 0; i < ncls && i < 200; i++)
            w = AppendFmt(w, txt + 0x10000, "0x%llX %lu 0x%llX 0x%llX 0x%llX\n",
                          rec[i].Vt, rec[i].Count, rec[i].Sample[0], rec[i].Sample[1], rec[i].Sample[2]);
        WriteFileAt(L"\\??\\C:\\ProgramData\\sc_classes.txt", txt,
                    (ULONG)(w - txt) + 1);
        KF("[mdump] cls done classes=%lu\n", ncls);
    } else {
        WriteFileAt(L"\\??\\C:\\ProgramData\\sc_ents.txt", txt, (ULONG)(w - txt) + 1);
        KF("[mdump] ent done vt=0x%llX bytes=%Id\n", wantVt, (INT_PTR)(w - txt));
    }
    ExFreePoolWithTag(txt, 'clst');
    ExFreePoolWithTag(rec, 'clsr');
}

static ULONG ScanWorldPos(PEPROCESS proc, U64 arrVa, const float cam[3], float out[][3], ULONG max)
{
    PUCHAR buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'scnW');
    ULONG found = 0;
    U64 off;
    if (!buf) return 0;
    for (off = 0; off < 0x200000 && found < max; off += 0x10000) {
        SIZE_T got = 0;
        ULONG k;
        if (!NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(arrVa + off), PsGetCurrentProcess(),
                                            buf, 0x10000, KernelMode, &got)) || got != 0x10000)
            continue;
        for (k = 0; k + 0x20 <= 0x10000 && found < max; k += 0x20) {
            U64 inst = *(U64*)(buf + k);
            float p[3];
            float dx, dy, dz, d2;
            U64 vt = 0;
            if (!inst || inst < 0x10000 || (inst >> 47)) continue;
            if (!ReadEntPos(proc, inst, p)) continue;
            dx = p[0]-cam[0]; dy = p[1]-cam[1]; dz = p[2]-cam[2];
            d2 = dx*dx + dy*dy + dz*dz;
            if (d2 < 400.0f || d2 > 4.0e9f) continue;   /* 0.4m ~ 1100m???????? */
            out[found][0] = p[0]; out[found][1] = p[1]; out[found][2] = p[2];
            found++;
        }
    }
    ExFreePoolWithTag(buf, 'scnW');
    return found;
}

/* cached entity addresses: rebuilt occasionally, positions refreshed every tick */


/* ?????????????????? keep ? */
static VOID NearestSort(U64* addr, float* dist, ULONG n, ULONG keep)
{
    ULONG i, j;
    for (i = 1; i < n; i++) {
        U64  a = addr[i];
        float d = dist[i];
        j = i;
        while (j > 0 && dist[j - 1] > d) {
            addr[j] = addr[j - 1];
            dist[j] = dist[j - 1];
            j--;
        }
        addr[j] = a;
        dist[j] = d;
    }
    if (n > keep) {
        for (i = keep; i < n; i++) { addr[i] = 0; dist[i] = 0; }
    }
}


/* ?????????????????????????
 *   ????? / ??? : +0x978
 *   ??????        : +0x7830
 *   ????            : +0x376C
 * ????????????? */
static BOOLEAN ReadEntPos(PEPROCESS proc, U64 inst, float* out)
{
    static const ULONG kOff[3] = { 0x978, 0x7830, 0x376C };
    ULONG i;
    for (i = 0; i < 3; i++) {
        float t[3];
        if (!NT_SUCCESS(MemRead(proc, inst + kOff[i], t, 12))) continue;
        if (t[0] != t[0] || t[1] != t[1] || t[2] != t[2]) continue;
        if (t[0] < -60000.0f || t[0] > 60000.0f) continue;
        if (t[1] < -60000.0f || t[1] > 60000.0f) continue;
        if (t[2] < -60000.0f || t[2] > 60000.0f) continue;
        if (t[0] > -1.0f && t[0] < 1.0f && t[1] > -1.0f && t[1] < 1.0f) continue;
        out[0] = t[0]; out[1] = t[1]; out[2] = t[2];
        return TRUE;
    }
    return FALSE;
}

static VOID RebuildEntAddrs(PEPROCESS proc, U64 arrVa, const float cam[3], U64 wantVt)
{
    PUCHAR buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'rebA');
    static U64   s_candAddr[256];
    static float s_candDist[256];
    ULONG found = 0;
    U64 off;
    if (!buf) return;
    for (off = 0; off < 0x200000 && found < 64; off += 0x10000) {
        SIZE_T got = 0;
        ULONG k;
        if (!NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(arrVa + off), PsGetCurrentProcess(),
                                            buf, 0x10000, KernelMode, &got)) || got != 0x10000)
            continue;
        for (k = 0; k + 0x20 <= 0x10000 && found < 64; k += 0x20) {
            U64 inst = *(U64*)(buf + k);
            float p[3];
            float dx, dy, dz, d2;
            U64 vt = 0;
            if (!inst || inst < 0x10000 || (inst >> 47)) continue;
            /* ???"???"??????????????????? npc_dummie??
             * ???????????????????????
             * ???????????????? */
            if (wantVt) {
                if (!NT_SUCCESS(MemRead(proc, inst, &vt, 8)) || !vt) continue;
                if (vt != wantVt && vt != g_vtExtra && vt != g_vtExtra2) continue;
            }
            if (!NT_SUCCESS(MemRead(proc, inst + 0x978, p, 12))) continue;
            if (p[0] != p[0] || p[1] != p[1] || p[2] != p[2]) continue;
            if (p[0] < -60000.0f || p[0] > 60000.0f) continue;
            if (p[1] < -60000.0f || p[1] > 60000.0f) continue;
            if (p[2] < -60000.0f || p[2] > 60000.0f) continue;
            if (p[0] > -1.0f && p[0] < 1.0f && p[1] > -1.0f && p[1] < 1.0f) continue;
            dx = p[0]-cam[0]; dy = p[1]-cam[1]; dz = p[2]-cam[2];
            d2 = dx*dx + dy*dy + dz*dz;
            if (d2 < 400.0f || d2 > 4.0e9f) continue;   /* 0.4m ~ 1100m???????? */
            if (found < 256) {
                s_candAddr[found] = inst;
                s_candDist[found] = d2;
                found++;
            }
        }
    }
    NearestSort(s_candAddr, s_candDist, found, 64);
    {
        ULONG k2;
        ULONG keep = found > 64 ? 64 : found;
        g_entAddrCount = 0;
        for (k2 = 0; k2 < keep; k2++) {
            if (!s_candAddr[k2]) break;
            g_entAddr[g_entAddrCount++] = s_candAddr[k2];
        }
    }
    ExFreePoolWithTag(buf, 'rebA');
}

static ULONG RefreshEntPositions(PEPROCESS proc, const float cam[3], float out[][3], EINFO* info, ULONG max, U64 wantVt)
{
    ULONG i, n = 0;
    for (i = 0; i < g_entAddrCount && n < max; i++) {
        float p[3];
        float dx, dy, dz;
        UCHAR blk[0x520];
        if (!ReadEntPos(proc, g_entAddr[i], p)) continue;
        dx = p[0]-cam[0]; dy = p[1]-cam[1]; dz = p[2]-cam[2];
        if (dx*dx + dy*dy + dz*dz < 400.0f) continue;
        out[n][0] = p[0]; out[n][1] = p[1]; out[n][2] = p[2];
        /* ??? 0x520 ???????????+0x18C ~ +0x69C? */
        RtlZeroMemory(info[n].Name, sizeof(info[n].Name));
        info[n].Hp = info[n].HpMax = info[n].Sh = info[n].ShMax = 0;
        info[n].Team = 0; info[n].Life = 0; info[n].NameLen = 0; info[n].Flags = 0;
        {
            U64 vt = 0;
            BOOLEAN isPlayer = FALSE;
            if (NT_SUCCESS(MemRead(proc, g_entAddr[i], &vt, 8)) && vt) {
                if (wantVt && vt == wantVt) isPlayer = TRUE;
                if (g_vtExtra && vt == g_vtExtra) isPlayer = TRUE;
            }
            if (isPlayer && NT_SUCCESS(MemRead(proc, g_entAddr[i] + 0x18C, blk, sizeof(blk)))) {
            info[n].Sh    = *(ULONG*)(blk + 0x000);   /* +0x18C m_shieldHealth */
            info[n].ShMax = *(ULONG*)(blk + 0x004);   /* +0x190 m_shieldHealthMax */
            info[n].Hp    = *(ULONG*)(blk + 0x1A4);   /* +0x330 m_iHealth */
            info[n].HpMax = *(ULONG*)(blk + 0x2E4);   /* +0x470 m_iMaxHealth */
            info[n].Team  = *(UCHAR*)(blk + 0x1B4);   /* +0x340 m_iTeamNum */
            info[n].Life  = *(UCHAR*)(blk + 0x50C);   /* +0x698 m_lifeState */
            {
                ULONG k;
                for (k = 0; k < sizeof(info[n].Name) - 1; k++) {
                    UCHAR c = *(UCHAR*)(blk + 0x2F5 + k);   /* +0x481 m_iName */
                    if (c < 32 || c > 126) break;
                    info[n].Name[k] = (CHAR)c;
                    info[n].NameLen++;
                }
                info[n].Name[info[n].NameLen] = 0;
            }
                info[n].Flags = 1;
            }
        }
        n++;
    }
    return n;
}

static ULONG ScanSameClass(PEPROCESS proc, U64 arrVa, U64 vt, U64 self, float out[][3], ULONG max)
{
    PUCHAR buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'scnS');
    ULONG found = 0;
    U64 off;
    if (!buf) return 0;
    for (off = 0; off < 0x200000 && found < max; off += 0x10000) {
        SIZE_T got = 0;
        ULONG k;
        if (!NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(arrVa + off), PsGetCurrentProcess(),
                                            buf, 0x10000, KernelMode, &got)) || got != 0x10000)
            continue;
        for (k = 0; k + 0x20 <= 0x10000 && found < max; k += 0x20) {
            U64 inst = *(U64*)(buf + k);
            U64 ivt = 0;
            float p[3];
            if (!inst || inst < 0x10000 || (inst >> 47)) continue;
            if (inst == self) continue;
            if (!NT_SUCCESS(MemRead(proc, inst, &ivt, 8)) || ivt != vt) continue;
            if (!NT_SUCCESS(MemRead(proc, inst + 0x376C, p, 12))) continue;
            if (!(p[0] > -100000.0f && p[0] < 100000.0f && p[1] > -100000.0f && p[1] < 100000.0f)) continue;
            out[found][0] = p[0]; out[found][1] = p[1]; out[found][2] = p[2];
            found++;
        }
    }
    ExFreePoolWithTag(buf, 'scnS');
    return found;
}


static U64 g_modBase = 0;

static U64 ComputeModBase(PEPROCESS proc, PCWSTR name)
{
    U64 modBase = 0;
    KAPC_STATE apc; PPEB peb;
    KeStackAttachProcess(proc, &apc);
    peb = (PPEB)PsGetProcessPeb(proc);
    if (peb) {
        PVOID ldr = *(PVOID*)((PUCHAR)peb + 0x18);
        if (ldr) {
            LIST_ENTRY* head = (LIST_ENTRY*)((PUCHAR)ldr + 0x10);
            LIST_ENTRY* cur;
            UNICODE_STRING want;
            RtlInitUnicodeString(&want, name);
            for (cur = head->Flink; cur != head && cur; cur = cur->Flink) {
                PUCHAR e = (PUCHAR)cur; UNICODE_STRING bn;
                bn.Length = *(USHORT*)(e + 0x58); bn.MaximumLength = bn.Length;
                bn.Buffer = *(PWCH*)(e + 0x60);
                if (bn.Buffer && bn.Length && RtlEqualUnicodeString(&bn, &want, TRUE)) {
                    modBase = *(U64*)(e + 0x30); break;
                }
            }
        }
    }
    KeUnstackDetachProcess(&apc);
    return modBase;
}

/* ?????????????????????? */
static BOOLEAN TryReattach(void)
{
    LARGE_INTEGER ct; ULONG pid; PEPROCESS np = NULL; U64 nb;
    RtlZeroMemory(&ct, sizeof(ct));
    pid = FindPid(L"r5apex_dx12.exe", &ct);
    if (!pid) return FALSE;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &np))) return FALSE;
    if (PsGetProcessExitStatus(np) != STATUS_PENDING) { ObDereferenceObject(np); return FALSE; }
    nb = ComputeModBase(np, L"r5apex_dx12.exe");
    if (!nb) { ObDereferenceObject(np); return FALSE; }
    if (g_espProc) ObDereferenceObject(g_espProc);
    g_espProc = np;
    g_modBase = nb;
    if (!g_vtManual) {
        g_vtExtra  = nb + RVA_VT_NPC_DUMMIE;
        g_vtExtra2 = nb + RVA_VT_PLAYER;
        KF("[mdump] vtExtra reattach = 0x%llX / 0x%llX\n", g_vtExtra, g_vtExtra2);
    }
    KF("[mdump] reattached pid=%lu base=0x%llX\n", pid, nb);
    return TRUE;
}


/* ??????????????
 * ???????? parity???????????? contexts/focused/fade? */

/* ================= 整行高亮样式（HighlightSettings_t, stride 0x34）=================
 * 依据 UC [DX12] Highlight System 帖：
 *   +0x00 uint32 functionBits = {insideFunction, outsideFunction, outlineRadius, state|shouldDraw|postProcess}
 *   +0x04 Color color  (3 float)
 *   +0x10 Color color2 (3 float)
 *   +0x1C float nearFadeDist
 *   +0x20 float farFadeDist
 *   +0x24 uint32 focusedInside
 *   +0x28 uint32 focusedOutside
 *   +0x2C uint32 Flags          (eHIGHLIGHT_FLAG)
 *   +0x30 uint32 DrawFunc       (eHIGHLIGHT_VIS)
 *
 * 我们原来只改 RGB，Flags/DrawFunc/farFadeDist 全是行 50 的原生值，
 * 那些值带着视线检查/队伍要求/远距离淡出 —— 这就是高亮"有时出有时不出"的根因。
 */

static BOOLEAN PrefixIs(const UCHAR* p, const UCHAR* end, const char* tag)
{
    while (*tag) {
        if (p >= end || ((*p | 0x20) != (UCHAR)(*tag | 0x20))) return FALSE;
        p++; tag++;
    }
    return TRUE;
}

static BOOLEAN ParseUOpt(const UCHAR** pp, const UCHAR* end, ULONG* out)
{
    const UCHAR* p = *pp;
    ULONG v = 0; BOOLEAN seen = FALSE;
    while (p < end && *p == ' ') p++;
    while (p < end) {
        UCHAR c = *p;
        if (c >= '0' && c <= '9') { v = v * 10 + (ULONG)(c - '0'); seen = TRUE; p++; }
        else break;
    }
    *pp = p;
    if (seen) *out = v;
    return seen;
}

static BOOLEAN GlowRowAddr(PEPROCESS proc, U64 globalVa, ULONG row, U64* entry)
{
    U64 tbl = 0;
    if (!NT_SUCCESS(MemRead(proc, globalVa, &tbl, 8)) || !tbl) return FALSE;
    *entry = tbl + (U64)row * 0x34ULL;
    return TRUE;
}

/* 整行写入：保留 functionBits 的 mode 位，强制 shouldDraw|postProcess，清掉距离/视线限制 */
static VOID GlowSetupRow(PEPROCESS proc, U64 globalVa, ULONG row,
                         float r, float g, float b, ULONG flags, ULONG vis)
{
    U64 e = 0;
    ULONG bits = 0;
    float nf = 0.0f, ff = 200000.0f;

    if (!GlowRowAddr(proc, globalVa, row, &e)) {
        K("[mdump] glowrow: table ptr null\n");
        return;
    }
    if (!NT_SUCCESS(MemRead(proc, e, &bits, 4))) bits = 0xC040670Fu;   /* 行 50 原生值兜底 */
    {
        UCHAR b0 = (UCHAR)(bits & 0xFF);            /* insideFunction  */
        UCHAR b1 = (UCHAR)((bits >> 8) & 0xFF);     /* outsideFunction */
        UCHAR b2 = (UCHAR)((bits >> 16) & 0xFF);    /* outlineRadius   */
        UCHAR b3 = (UCHAR)((bits >> 24) & 0xFF);    /* state|draw|pp   */
        if (b2 == 0) b2 = 0x40;                     /* 半径 0 = 画不出来 */
        b3 |= 0xC0;                                 /* shouldDraw | postProcess */
        bits = (ULONG)b0 | ((ULONG)b1 << 8) | ((ULONG)b2 << 16) | ((ULONG)b3 << 24);
    }
    MemWrite(proc, e + 0x00, &bits, 4);
    MemWrite(proc, e + 0x04, &r, 4);
    MemWrite(proc, e + 0x08, &g, 4);
    MemWrite(proc, e + 0x0C, &b, 4);
    MemWrite(proc, e + 0x10, &r, 4);                /* color2 同色 */
    MemWrite(proc, e + 0x14, &g, 4);
    MemWrite(proc, e + 0x18, &b, 4);
    MemWrite(proc, e + 0x1C, &nf, 4);               /* nearFadeDist = 0  */
    MemWrite(proc, e + 0x20, &ff, 4);               /* farFadeDist  = 200000 */
    MemWrite(proc, e + 0x2C, &flags, 4);            /* 去掉队伍/视线要求 */
    MemWrite(proc, e + 0x30, &vis, 4);              /* DrawFunc = ALWAYS */
    KF("[mdump] glowrow row=%lu rgb=(%ld,%ld,%ld) flags=0x%X vis=%lu bits=0x%08X entry=0x%llX [x100]\n",
       row, (long)(r * 100), (long)(g * 100), (long)(b * 100), flags, vis, bits, e);
}

static VOID GlowDumpRow(PEPROCESS proc, U64 globalVa, ULONG row)
{
    U64 e = 0;
    UCHAR buf[0x34];
    CHAR line[256];
    CHAR* w = line;
    ULONG i;
    if (!GlowRowAddr(proc, globalVa, row, &e)) { K("[mdump] glowdump: table null\n"); return; }
    if (!NT_SUCCESS(MemRead(proc, e, buf, 0x34))) { K("[mdump] glowdump: read fail\n"); return; }
    KF("[mdump] glowdump row=%lu entry=0x%llX\n", row, e);
    for (i = 0; i < 0x34; i++) {
        static const CHAR hx[] = "0123456789ABCDEF";
        *w++ = hx[buf[i] >> 4];
        *w++ = hx[buf[i] & 0xF];
        *w++ = (i % 16 == 15) ? '\n' : ' ';
        if (i % 16 == 15 || i == 0x33) { *w = 0; K(line); w = line; }
    }
    {
        ULONG bits; float rr, gg, bb;
        ULONG fl, vis;
        MemRead(proc, e + 0x00, &bits, 4);
        MemRead(proc, e + 0x04, &rr, 4); MemRead(proc, e + 0x08, &gg, 4); MemRead(proc, e + 0x0C, &bb, 4);
        MemRead(proc, e + 0x2C, &fl, 4); MemRead(proc, e + 0x30, &vis, 4);
        KF("[mdump]   functionBits=0x%08X  radius=%lu shouldDraw=%lu pp=%lu\n",
           bits, (unsigned long)((bits >> 16) & 0xFF), (unsigned long)((bits >> 30) & 1), (unsigned long)((bits >> 31) & 1));
        KF("[mdump]   color=(%ld,%ld,%ld) flags=0x%X drawFunc=%lu [x100]\n",
           (long)(rr * 100), (long)(gg * 100), (long)(bb * 100), fl, vis);
    }
}

/* 找全零行（可安全克隆） */
static VOID GlowFindFree(PEPROCESS proc, U64 globalVa)
{
    U64 tbl = 0;
    ULONG row;
    CHAR line[512];
    CHAR* w = line;
    ULONG n = 0;
    if (!NT_SUCCESS(MemRead(proc, globalVa, &tbl, 8)) || !tbl) { K("[mdump] glowfind: table null\n"); return; }
    KF("[mdump] glowfind table=0x%llX\n", tbl);
    for (row = 0; row < 256; row++) {
        UCHAR buf[0x34]; ULONG i; BOOLEAN zero = TRUE;
        if (!NT_SUCCESS(MemRead(proc, tbl + (U64)row * 0x34ULL, buf, 0x34))) continue;
        for (i = 0; i < 0x34; i++) if (buf[i] != 0) { zero = FALSE; break; }
        if (zero) {
            w += RtlStringCchPrintfA(w, (size_t)(line + sizeof(line) - w), "%lu ", row);
            n++;
            if (n % 20 == 0) { *w = 0; K(line); w = line; }
        }
    }
    if (w != line) { *w = 0; K(line); }
    KF("[mdump] glowfind zero_rows=%lu\n", n);
}

static VOID GlowCloneRow(PEPROCESS proc, U64 globalVa, ULONG src, ULONG dst)
{
    U64 tbl = 0;
    UCHAR buf[0x34];
    if (!NT_SUCCESS(MemRead(proc, globalVa, &tbl, 8)) || !tbl) { K("[mdump] glowclone: table null\n"); return; }
    if (!NT_SUCCESS(MemRead(proc, tbl + (U64)src * 0x34ULL, buf, 0x34))) { K("[mdump] glowclone: src read fail\n"); return; }
    MemWrite(proc, tbl + (U64)dst * 0x34ULL, buf, 0x34);
    KF("[mdump] glowclone %lu -> %lu (0x34 bytes)\n", src, dst);
}


/* ============ 骨骼矩阵数组搜索（依据 UC Wiki 骨骼索引表）============
 * 索引: 0=delta 根, 4=hip, 7=spineC, 11=neckB, 12=head, 共 176 根
 * 每个骨骼是一条 3x4 矩阵，平移分量在矩阵内 +0x0C（float[3], [7], [11]）
 */

static float FabsF(float v) { return (v < 0.0f) ? -v : v; }

static BOOLEAN ReadBoneTrans(PEPROCESS proc, U64 base, ULONG stride, ULONG idx, float* out)
{
    return NT_SUCCESS(MemRead(proc, base + (U64)idx * stride + 0x0C, out, 12));
}

static BOOLEAN BoneChainSig(PEPROCESS proc, U64 base, ULONG stride, float* headOut, float* originOut)
{
    float t0[3], t4[3], t7[3], t11[3], t12[3];
    float dz1, dz2, dz3, height;
    if (!ReadBoneTrans(proc, base, stride, 0, t0))  return FALSE;
    if (!ReadBoneTrans(proc, base, stride, 4, t4))  return FALSE;
    if (!ReadBoneTrans(proc, base, stride, 7, t7))  return FALSE;
    if (!ReadBoneTrans(proc, base, stride, 11, t11)) return FALSE;
    if (!ReadBoneTrans(proc, base, stride, 12, t12)) return FALSE;

    /* 全部有限且在合理地图范围内 */
    if (!(t0[0] > -40000.0f && t0[0] < 40000.0f)) return FALSE;
    if (!(t12[2] > -5000.0f && t12[2] < 5000.0f)) return FALSE;
    if (t0[0] != t0[0] || t12[0] != t12[0]) return FALSE;

    /* 垂直链：x/y 相近 */
    if (FabsF(t4[0] - t7[0]) > 12.0f) return FALSE;
    if (FabsF(t4[1] - t7[1]) > 12.0f) return FALSE;
    if (FabsF(t7[0] - t12[0]) > 25.0f) return FALSE;
    if (FabsF(t7[1] - t12[1]) > 25.0f) return FALSE;

    /* z 单调递增 */
    dz1 = t7[2] - t4[2];
    dz2 = t11[2] - t7[2];
    dz3 = t12[2] - t11[2];
    if (dz1 <= 0.0f || dz3 <= 0.0f) return FALSE;
    height = t12[2] - t4[2];
    if (height < 20.0f || height > 120.0f) return FALSE;

    if (headOut)   { headOut[0] = t12[0]; headOut[1] = t12[1]; headOut[2] = t12[2]; }
    if (originOut) { originOut[0] = t0[0]; originOut[1] = t0[1]; originOut[2] = t0[2]; }
    return TRUE;
}

static VOID BoneScan(PEPROCESS proc, U64 ent)
{
    CHAR* txt = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x8000, 'bsct');
    CHAR* w;
    ULONG off, hits = 0;
    static const ULONG strides[2] = { 0x30, 0x40 };

    if (!txt) return;
    RtlZeroMemory(txt, 0x8000); w = txt; w[0] = 0;
    w = AppendFmt(w, txt + 0x8000, "bonescan ent=0x%llX\n", ent);

    for (off = 0x10; off < 0x2000; off += 8) {
        U64 p = 0;
        ULONG si;
        if (!NT_SUCCESS(MemRead(proc, ent + off, &p, 8))) continue;
        if (!p || p < 0x10000 || (p >> 47)) continue;
        for (si = 0; si < 2; si++) {
            float head[3], orig[3];
            if (BoneChainSig(proc, p, strides[si], head, orig)) {
                w = AppendFmt(w, txt + 0x8000,
                    "HIT field+0x%X -> 0x%llX stride=0x%X\n", off, p, strides[si]);
                w = AppendFmt(w, txt + 0x8000,
                    "    origin=(%.1f,%.1f,%.1f) head=(%.1f,%.1f,%.1f) h=%.1f\n",
                    orig[0], orig[1], orig[2], head[0], head[1], head[2], head[2] - orig[2]);
                hits++;
                if (hits >= 8) goto done;
            }
        }
    }
done:
    w = AppendFmt(w, txt + 0x8000, "hits=%lu\n", hits);
    WriteFileAt(L"\\??\\C:\\ProgramData\\sc_bonescan.txt", txt, (ULONG)(w - txt) + 1);
    KF("[mdump] bonescan done hits=%lu\n", hits);
    ExFreePoolWithTag(txt, 'bsct');
}

/* 指定数组直接按骨骼索引读位置（验证用） */
static VOID BoneDump(PEPROCESS proc, U64 base, ULONG stride, ULONG idx)
{
    CHAR* txt = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x4000, 'bdmp');
    CHAR* w;
    ULONG i;
    if (!txt) return;
    RtlZeroMemory(txt, 0x4000); w = txt; w[0] = 0;
    w = AppendFmt(w, txt + 0x4000, "bonedump base=0x%llX stride=0x%X idx=%lu\n", base, stride, idx);
    for (i = 0; i < 176; i++) {
        float t[3];
        if (!ReadBoneTrans(proc, base, stride, i, t)) { w = AppendFmt(w, txt + 0x4000, "read fail at %lu\n", i); break; }
        if (i == 0 || i == 4 || i == 7 || i == 11 || i == 12 ||
            (idx && i == idx)) {
            w = AppendFmt(w, txt + 0x4000, "  [%3lu] (%.2f, %.2f, %.2f)\n", i, t[0], t[1], t[2]);
        }
        if (w > txt + 0x3800) break;
    }
    WriteFileAt(L"\\??\\C:\\ProgramData\\sc_bonedump.txt", txt, (ULONG)(w - txt) + 1);
    K("[mdump] bonedump written\n");
    ExFreePoolWithTag(txt, 'bdmp');
}


/* dump 实体 0x280~0x2C4，帮助定位 selector / contexts / focused / parity */
static VOID GlowFields(PEPROCESS proc, U64 ent)
{
    UCHAR buf[0x48];
    CHAR* txt;
    CHAR* w;
    ULONG i;

    txt = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x4000, 'gfld');
    if (!txt) return;
    RtlZeroMemory(txt, 0x4000); w = txt; w[0] = 0;

    w = AppendFmt(w, txt + 0x4000, "glowfields ent=0x%llX  [0x280..0x2C7]\n", ent);
    if (!NT_SUCCESS(MemRead(proc, ent + 0x280, buf, sizeof(buf)))) {
        w = AppendFmt(w, txt + 0x4000, "read fail\n");
        WriteFileAt(L"\\??\\C:\\ProgramData\\sc_glowfields.txt", txt, (ULONG)(w - txt) + 1);
        ExFreePoolWithTag(txt, 'gfld');
        return;
    }
    for (i = 0; i < sizeof(buf); i += 16) {
        w = AppendFmt(w, txt + 0x4000, "  +0x%03X  %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X\n",
            (unsigned)(0x280 + i),
            buf[i+0], buf[i+1], buf[i+2], buf[i+3], buf[i+4], buf[i+5], buf[i+6], buf[i+7],
            buf[i+8], buf[i+9], buf[i+10], buf[i+11], buf[i+12], buf[i+13], buf[i+14], buf[i+15]);
    }
    /* 逐候选解释 */
    {
        ULONG cand[10] = { 0x294, 0x295, 0x29D, 0x29F, 0x2A0, 0x2A1, 0x2A8, 0x2AC, 0x2B4, 0x2B8 };
        for (i = 0; i < 10; i++) {
            ULONG off = cand[i];
            if (off - 0x280 + 4 > sizeof(buf)) continue;
            {
                ULONG d; float f;
                UCHAR by = buf[off - 0x280];
                RtlCopyMemory(&d, buf + (off - 0x280), 4);
                RtlCopyMemory(&f, buf + (off - 0x280), 4);
                w = AppendFmt(w, txt + 0x4000,
                    "  +0x%03X  byte=0x%02X(%3u)  dword=0x%08X(%u)  float=%.4f\n",
                    off, by, (unsigned)by, d, d, f);
            }
        }
        w = AppendFmt(w, txt + 0x4000,
            "\n当前驱动使用: sel=0x%X ctx=0x%X focus=0x%X fade=0x%X parity=0x%X\n",
            g_selOff, g_ctxOff, g_focusOff, g_fadeOff, g_parOff);
        w = AppendFmt(w, txt + 0x4000,
            "判定: selector 通常是 0xFF(无效) 或 0..127 的小整数\n");
    }
    WriteFileAt(L"\\??\\C:\\ProgramData\\sc_glowfields.txt", txt, (ULONG)(w - txt) + 1);
    K("[mdump] glowfields written\n");
    ExFreePoolWithTag(txt, 'gfld');
}

static VOID AutoGlowAll(PEPROCESS proc)
{
    UCHAR row = (UCHAR)(g_autoRow & 0xFF);
    ULONG one = 1;
    float fd = 1.0f;
    ULONG i, j, newN = 0;
    U64 newCache[64];

    if (!g_autoGlow || !proc) return;

    /* ??????????/??????????? 240ms ???? */
    if (modBaseForNpc) {
        U64 gva = modBaseForNpc + RVA_HIGHLIGHT_GLOBAL;
        /* 整行写：颜色 + 清掉距离/视线/队伍限制 */
        GlowSetupRow(proc, gva, g_autoRow, g_autoR, g_autoG, g_autoB, g_autoFlags, g_autoVis);
        /* —— 样式行运行时校验 ——
         * 引擎在换图/回合重置时可能回收复用这一行，被改写就重新设置 */
        {
            static ULONG chk = 0;
            if ((++chk % 8) == 0) {
                U64 e = 0;
                if (GlowRowAddr(proc, gva, g_autoRow, &e)) {
                    ULONG fl = 0, vis = 0xFFFFFFFF;
                    BOOLEAN bad = FALSE;
                    if (!NT_SUCCESS(MemRead(proc, e + 0x2C, &fl, 4))) bad = TRUE;
                    else if (fl != g_autoFlags) bad = TRUE;
                    if (!NT_SUCCESS(MemRead(proc, e + 0x30, &vis, 4))) bad = TRUE;
                    else if (vis != g_autoVis) bad = TRUE;
                    if (bad) {
                        GlowSetupRow(proc, gva, g_autoRow, g_autoR, g_autoG, g_autoB, g_autoFlags, g_autoVis);
                        KF("[mdump] glowrow reclaimed, re-applied (flags=0x%X vis=%lu)\n", fl, vis);
                    }
                }
            }
        }
    }

    for (i = 0; i < g_entAddrCount && newN < 64; i++) {
        U64 e = g_entAddr[i];
        BOOLEAN seen = FALSE;
        if (!e) continue;
        for (j = 0; j < g_glowCacheN; j++) {
            if (g_glowCache[j] == e) { seen = TRUE; break; }
        }
        /* 四步（按 UC 帖子）：selector 是渲染器真正读的那个，必须先写 */
        MemWrite(proc, e + g_selOff, &row, 1);
        MemWrite(proc, e + g_ctxOff, &row, 1);
        MemWrite(proc, e + g_focusOff, &one, 4);
        MemWrite(proc, e + g_fadeOff, &fd, 4);
        if (!seen) {
            ULONG pv = 0;
            if (NT_SUCCESS(MemRead(proc, e + 0x2B4, &pv, 4))) {
                pv ^= 1;
                MemWrite(proc, e + 0x2B4, &pv, 4);
            }
        }
        newCache[newN++] = e;
    }
    for (i = 0; i < newN; i++) g_glowCache[i] = newCache[i];
    g_glowCacheN = newN;
}

static VOID EspLoop(PEPROCESS proc, U64 modBase);
static VOID EspThread(PVOID ctx)
{
    EspLoop(g_espProc, (U64)(ULONG_PTR)ctx);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID EspLoop(PEPROCESS proc0, U64 modBase0)
{
    PEPROCESS proc = proc0; U64 modBase = modBase0;
    FEED f;
    ULONG tick = 0;

    KF("[mdump] esp loop start, module=0x%llX\n", modBase);
    for (;;) {
        ULONG h = 0xFFFFFFFF;
        GlowTick(proc);
        if (!TGT_ALIVE()) {
            if (TryReattach()) { proc = g_espProc; modBase = g_modBase; continue; }
            SleepMs(1000); continue;
        }
        RtlZeroMemory(&f, sizeof(f));
        f.Magic = 0x44454546;     /* 'FEED' */
        f.Version = 2;

        if (NT_SUCCESS(MemRead(proc, modBase + RVA_LOCAL_HANDLE, &h, 4)) && h != 0xFFFFFFFF) {
            ULONG idx = h & 0xFFFF;
            ULONG ser = h >> 16;
            U64 entry = modBase + RVA_ENTITY_ARRAY + (U64)idx * ENT_STRIDE;
            U64 inst = 0;
            ULONG eser = 0;
            if (NT_SUCCESS(MemRead(proc, entry, &inst, 8)) &&
                NT_SUCCESS(MemRead(proc, entry + 8, &eser, 4)) &&
                inst && eser == ser) {
                f.Inst = inst;
                MemRead(proc, inst + OFF_CAMERA, f.Cam, 12);
                MemRead(proc, inst + OFF_ANGLES, f.Ang, 12);
                MemRead(proc, inst + OFF_ORIGIN, f.Pos, 12);
                f.Ok = 1;
            }
        }
        if (f.Ok) {
            static float s_ent[FEED_MAX_ENT][3];
            U64 lvt = 0;
            if (f.Inst) MemRead(proc, f.Inst, &lvt, 8);
            if ((tick % 120) == 0) {
                RebuildEntAddrs(proc, modBase + RVA_ENTITY_ARRAY, f.Cam, lvt);
            }
            g_entCount = RefreshEntPositions(proc, f.Cam, s_ent, f.Info, FEED_MAX_ENT, lvt);
            if ((tick % 15) == 0) AutoGlowAll(proc);
            RtlCopyMemory(g_entList, s_ent, sizeof(s_ent));
        }
        f.Count = g_entCount;
        if (g_entCount) RtlCopyMemory(f.Ent, g_entList, sizeof(float) * 3 * FEED_MAX_ENT);
        {   /* persistent handle; on any failure close and reopen next tick */
            IO_STATUS_BLOCK io; LARGE_INTEGER off; NTSTATUS st;
            if (!g_feedHandle) {
                UNICODE_STRING up2; OBJECT_ATTRIBUTES oa2;
                RtlInitUnicodeString(&up2, FEED_FILE);
                InitializeObjectAttributes(&oa2, &up2, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);
                st = ZwCreateFile(&g_feedHandle, GENERIC_WRITE|SYNCHRONIZE, &oa2, &io, NULL,
                                  FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ|FILE_SHARE_WRITE,
                                  FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
                if (!NT_SUCCESS(st)) { g_feedHandle = NULL; SleepMs(20); continue; }
            }
            off.QuadPart = 0;
            st = ZwWriteFile(g_feedHandle, NULL, NULL, NULL, &io, &f, sizeof(f), &off, NULL);
            if (!NT_SUCCESS(st)) { ZwClose(g_feedHandle); g_feedHandle = NULL; }
        }
        if ((tick++ % 120) == 0)
            KF("[mdump] esp tick ok=%lu inst=0x%llX cam=(%.1f,%.1f,%.1f) ang=(%.1f,%.1f)\n",
               f.Ok, f.Inst, f.Cam[0], f.Cam[1], f.Cam[2], f.Ang[0], f.Ang[1]);
        SleepMs(16);
    }
}

static VOID Waiter(PVOID ctx)
{
    LARGE_INTEGER dl, ct, ct2;
    ULONG waited = 0, pid = 0, last = 0, stable = 0;
    PEPROCESS proc = NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(ctx);
    ct.QuadPart = 0;
    K("[mdump] waiter alive\n");
    for (;;) {
        pid = FindPid(L"r5apex_dx12.exe", &ct2);
        if (pid && pid == last && ct2.QuadPart == ct.QuadPart) stable += 10;
        else { last = pid; ct = ct2; stable = 0; }
        if (pid && stable >= 20000) break;
        dl.QuadPart = -100000LL;   /* 10ms */
        KeDelayExecutionThread(KernelMode, FALSE, &dl);
        waited += 10;
        if (waited > 1800000) { K("[mdump] timeout\n"); PsTerminateSystemThread(STATUS_TIMEOUT); }
    }
    KF("[mdump] game pid=%lu\n", pid);
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    if (!NT_SUCCESS(st)) { KF("[mdump] lookup=0x%X\n", st); PsTerminateSystemThread(st); }
    /* resident mode: serve snap requests until reboot */
    {
        U64 modBase = 0, modData[4]; ULONG modSz[4], modN = 0;
        {   KAPC_STATE apc; PPEB peb;
            KeStackAttachProcess(proc, &apc);
            peb = (PPEB)PsGetProcessPeb(proc);
            if (peb) {
                PVOID ldr = *(PVOID*)((PUCHAR)peb + 0x18);
                if (ldr) {
                    LIST_ENTRY* head = (LIST_ENTRY*)((PUCHAR)ldr + 0x10);
                    LIST_ENTRY* cur; UNICODE_STRING want;
                    RtlInitUnicodeString(&want, L"r5apex_dx12.exe");
                    for (cur = head->Flink; cur != head && cur; cur = cur->Flink) {
                        PUCHAR e = (PUCHAR)cur; UNICODE_STRING bn;
                        bn.Length = *(USHORT*)(e + 0x58); bn.MaximumLength = bn.Length;
                        bn.Buffer = *(PWCH*)(e + 0x60);
                        if (bn.Buffer && bn.Length && RtlEqualUnicodeString(&bn, &want, TRUE)) { modBase = *(U64*)(e + 0x30); break; }
                    }
                }
            }
            KeUnstackDetachProcess(&apc);
        }
        KF("[mdump] resident, module=0x%llX\n", modBase);
        modBaseForNpc = modBase;
        if (modBase && !g_vtManual) {
            g_vtExtra  = modBase + RVA_VT_NPC_DUMMIE;
            g_vtExtra2 = modBase + RVA_VT_PLAYER;
            KF("[mdump] vtExtra auto = 0x%llX / 0x%llX\n", g_vtExtra, g_vtExtra2);
        }
        g_espProc = proc;
        if (modBase) {
            U64 nt = 0; ULONG nsec, so, i;
            KAPC_STATE apc;
            KeStackAttachProcess(proc, &apc);
            nt = modBase + *(ULONG*)(ULONG_PTR)(modBase + 0x3C);
            nsec = *(USHORT*)(ULONG_PTR)(nt + 6);
            so = *(USHORT*)(ULONG_PTR)(nt + 20);
            for (i = 0; i < nsec && modN < 4; i++) {
                PUCHAR sh = (PUCHAR)(nt + 24 + so + i * 40);
                if ((sh[0]=='.'&&sh[1]=='d'&&sh[2]=='a') || (sh[0]=='.'&&sh[1]=='r'&&sh[2]=='d')) {
                    modData[modN] = modBase + *(ULONG*)(sh + 12);
                    modSz[modN] = *(ULONG*)(sh + 8);
                    modN++;
                }
            }
            KeUnstackDetachProcess(&apc);
        }
        {   HANDLE eh = NULL;
            NTSTATUS est = PsCreateSystemThread(&eh, THREAD_ALL_ACCESS, NULL, NULL, NULL,
                                                EspThread, (PVOID)(ULONG_PTR)modBase);
            KF("[mdump] esp thread=0x%X\n", est);
            if (NT_SUCCESS(est) && eh) ZwClose(eh);
        }
        ServeRequests(proc, modData, modSz, modN);
    }
    ObDereferenceObject(proc);
    K("[mdump] done\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT D, PUNICODE_STRING R)
{
    HANDLE h = NULL; NTSTATUS st;
    UNREFERENCED_PARAMETER(D); UNREFERENCED_PARAMETER(R);
    ExInitializeFastMutex(&g_ioMutex);
    K("\n[mdump] === entry ===\n");
    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL, Waiter, NULL);
    if (NT_SUCCESS(st) && h) ZwClose(h);
    { LARGE_INTEGER d; d.QuadPart = -30000000LL; KeDelayExecutionThread(KernelMode, FALSE, &d); }
    return STATUS_SUCCESS;
}
