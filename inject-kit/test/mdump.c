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
    ULONG done_total = 0;

    if (len > REGION_CAP) len = REGION_CAP;
    RtlInitUnicodeString(&p, path);
    InitializeObjectAttributes(&oa, &p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, GENERIC_WRITE | SYNCHRONIZE, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL,
                                 FILE_SHARE_READ, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
        return 0;

    while (done_total < len) {
        ULONG chunk = len - done_total;
        SIZE_T got = 0;
        if (chunk > 0x10000) chunk = 0x10000;      /* 64KB steps: one bad page never kills the range */
        RtlZeroMemory(buf, chunk);
        if (!NT_SUCCESS(MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)(va + done_total), PsGetCurrentProcess(),
                                            buf, chunk, KernelMode, &got)) || got != chunk) {
            /* page not readable: keep zeros, keep going */
            chunk = (ULONG)min(chunk, 0x10000u);
        }
        if (!NT_SUCCESS(ZwWriteFile(h, NULL, NULL, NULL, &io, buf, chunk, NULL, NULL)))
            break;
        done_total += chunk;
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
            m.Size >= 0x10000 && m.Size <= 0x04000000ULL) {
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
static U64 modBaseForNpc = 0;

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
static VOID WriteVa(PEPROCESS proc, UCHAR* p, UCHAR* le);

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
                        if ((p[0] == 'w' || p[0] == 'W') && (p[1] == 'l' || p[1] == 'L')) {
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

typedef struct _FEED {
    ULONG Magic;        /* 'FEED' */
    ULONG Version;      /* 3 */
    float Cam[3];
    float Ang[3];
    float Pos[3];
    ULONG Count;        /* players of the same class */
    ULONG Ok;
    U64   Inst;
    float Ent[FEED_MAX_ENT][3];
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
            if (!NT_SUCCESS(MemRead(proc, inst + 0x978, p, 12))) continue;
            if (p[0] != p[0] || p[1] != p[1] || p[2] != p[2]) continue;
            if (p[0] < -40000.0f || p[0] > 40000.0f) continue;
            if (p[1] < -40000.0f || p[1] > 40000.0f) continue;
            if (p[2] < -40000.0f || p[2] > 40000.0f) continue;
            if (p[0] > -1.0f && p[0] < 1.0f && p[1] > -1.0f && p[1] < 1.0f) continue;
            dx = p[0]-cam[0]; dy = p[1]-cam[1]; dz = p[2]-cam[2];
            d2 = dx*dx + dy*dy + dz*dz;
            if (d2 < 2500.0f || d2 > 100000000.0f) continue;
            out[found][0] = p[0]; out[found][1] = p[1]; out[found][2] = p[2];
            found++;
        }
    }
    ExFreePoolWithTag(buf, 'scnW');
    return found;
}

/* cached entity addresses: rebuilt occasionally, positions refreshed every tick */

static VOID RebuildEntAddrs(PEPROCESS proc, U64 arrVa, const float cam[3], U64 wantVt)
{
    PUCHAR buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, 'rebA');
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
            if (wantVt) {
                if (!NT_SUCCESS(MemRead(proc, inst, &vt, 8)) || vt != wantVt) continue;
            }
            if (!NT_SUCCESS(MemRead(proc, inst + 0x978, p, 12))) continue;
            if (p[0] != p[0] || p[1] != p[1] || p[2] != p[2]) continue;
            if (p[0] < -40000.0f || p[0] > 40000.0f) continue;
            if (p[1] < -40000.0f || p[1] > 40000.0f) continue;
            if (p[2] < -40000.0f || p[2] > 40000.0f) continue;
            if (p[0] > -1.0f && p[0] < 1.0f && p[1] > -1.0f && p[1] < 1.0f) continue;
            dx = p[0]-cam[0]; dy = p[1]-cam[1]; dz = p[2]-cam[2];
            d2 = dx*dx + dy*dy + dz*dz;
            if (d2 < 2500.0f || d2 > 100000000.0f) continue;
            g_entAddr[found++] = inst;
        }
    }
    g_entAddrCount = found;
    ExFreePoolWithTag(buf, 'rebA');
}

static ULONG RefreshEntPositions(PEPROCESS proc, const float cam[3], float out[][3], ULONG max)
{
    ULONG i, n = 0;
    for (i = 0; i < g_entAddrCount && n < max; i++) {
        float p[3];
        float dx, dy, dz;
        if (!NT_SUCCESS(MemRead(proc, g_entAddr[i] + 0x978, p, 12))) continue;
        if (p[0] != p[0] || p[1] != p[1] || p[2] != p[2]) continue;
        if (p[0] < -40000.0f || p[0] > 40000.0f) continue;
        if (p[1] < -40000.0f || p[1] > 40000.0f) continue;
        if (p[2] < -40000.0f || p[2] > 40000.0f) continue;
        dx = p[0]-cam[0]; dy = p[1]-cam[1]; dz = p[2]-cam[2];
        if (dx*dx + dy*dy + dz*dz < 2500.0f) continue;
        out[n][0] = p[0]; out[n][1] = p[1]; out[n][2] = p[2]; n++;
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
    KF("[mdump] reattached pid=%lu base=0x%llX\n", pid, nb);
    return TRUE;
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
            if ((tick % 120) == 0) {
                U64 lvt = 0;
                if (f.Inst) MemRead(proc, f.Inst, &lvt, 8);
                RebuildEntAddrs(proc, modBase + RVA_ENTITY_ARRAY, f.Cam, lvt);
            }
            g_entCount = RefreshEntPositions(proc, f.Cam, s_ent, FEED_MAX_ENT);
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
