/*
 * kmap.c — 内核态"零句柄"注入器（Javelin / EAC 环境用）
 *
 * 设计要点：
 *   1) 全程不调用 OpenProcess，不创建任何目标进程句柄 —— 反作弊的
 *      ObRegisterCallbacks(PreOperation) 只能裁剪"句柄"，没有句柄就无从裁剪。
 *   2) 用 PsLookupProcessByProcessId 拿 EPROCESS，KeStackAttachProcess 切地址空间，
 *      ZwAllocateVirtualMemory / RtlCopyMemory 直接在目标 VA 上落地 PE 镜像。
 *   3) 手动映射：分节映射 + 基址重定位 + 目标侧导入表解析（遍历目标 PEB->Ldr）。
 *   4) 执行：往目标写一小段 x64 壳，再用 KeInsertQueueApc(UserMode) 投递到目标线程。
 *   5) 读写原语：attach + probe，不走 MmCopyMemory（避开 Javelin 的 inline hook）。
 *
 * 仅用于本地沙箱/测试环境。
 */

#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#define KMAP_POOL   'PAMK'
#define KMAP_DEVICE L"\\Device\\KmapDrv"
#define KMAP_LINK   L"\\DosDevices\\KmapDrv"

/* ------------------------------------------------------------------
 * WDK 26100 的 km 头里没有这些：PEB/Ldr 结构、APC API、ZwProtectVirtualMemory、
 * PsGetNextProcessThread。自己补最小定义（x64 布局）。
 * ------------------------------------------------------------------ */

typedef struct _KMAP_LDR_ENTRY
{
    LIST_ENTRY     InLoadOrderLinks;       // +0x00
    LIST_ENTRY     InMemoryOrderLinks;     // +0x10
    LIST_ENTRY     InInitializationOrderLinks; // +0x20
    PVOID          DllBase;                // +0x30
    PVOID          EntryPoint;             // +0x38
    ULONG          SizeOfImage;            // +0x40
    UNICODE_STRING FullDllName;            // +0x48
    UNICODE_STRING BaseDllName;            // +0x58
} KMAP_LDR_ENTRY, *PKMAP_LDR_ENTRY;

typedef struct _KMAP_PEB_LDR
{
    ULONG      Length;                     // +0x00
    UCHAR      Initialized;                // +0x04
    PVOID      SsHandle;                   // +0x08
    LIST_ENTRY InLoadOrderModuleList;      // +0x10
} KMAP_PEB_LDR, *PKMAP_PEB_LDR;

#define KMAP_PEB_LDR_OFFSET 0x18           // PEB->Ldr

#define KMAP_CURRENT_PEB ((PVOID)__readgsqword(0x60))

typedef VOID (*KMAP_NORMAL_ROUTINE)(PVOID, PVOID, PVOID);
typedef VOID (*KMAP_KERNEL_ROUTINE)(PVOID, KMAP_NORMAL_ROUTINE*, PVOID*, PVOID*, PVOID*);

NTSYSAPI VOID NTAPI KeInitializeApc(PVOID Apc, PVOID Thread, CCHAR Environment,
                                    PVOID KernelRoutine, PVOID RundownRoutine,
                                    PVOID NormalRoutine, CCHAR ApcMode,
                                    PVOID NormalContext);
NTSYSAPI BOOLEAN NTAPI KeInsertQueueApc(PVOID Apc, PVOID SystemArgument1,
                                        PVOID SystemArgument2, CCHAR PriorityBoost);
NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
                                               PSIZE_T RegionSize, ULONG NewProtect,
                                               PULONG OldProtect);
NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
NTSYSAPI NTSTATUS NTAPI RtlCreateUserThread(HANDLE ProcessHandle,
                                            PSECURITY_DESCRIPTOR SecurityDescriptor,
                                            BOOLEAN CreateSuspended, ULONG StackZeroBits,
                                            SIZE_T StackReserve, SIZE_T StackCommit,
                                            PVOID StartAddress, PVOID StartParameter,
                                            PHANDLE ThreadHandle, PCLIENT_ID ClientId);

/* Flag bit1：用 NtCreateThreadEx 建线程执行（不依赖 APC 的可告警等待） */
#define KMAP_FLAG_MAP_ONLY   0x1
#define KMAP_FLAG_NEW_THREAD 0x2
#define KMAP_FLAG_PROBE      0x4
#define KMAP_FLAG_LOADLIB    0x8

#define KMAP_APC_ENV_ORIGINAL 0
#define KMAP_MODE_USER        1


#define KMAP_IOCTL_PING      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KMAP_IOCTL_INJECT    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KMAP_IOCTL_READ      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KMAP_IOCTL_WRITE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KMAP_IOCTL_GETBASE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define KMAP_MAX_TIDS 256

typedef struct _KMAP_INJECT_REQ
{
    ULONG  ProcessId;
    ULONG  ThreadId;              // 单线程投递（保留兼容）
    ULONG  Flags;                 // bit0: 只映射不执行（调试用）
    ULONG  ThreadCount;           // 0 = 只投 ThreadId
    WCHAR  DllPath[512];
    ULONG  ThreadIds[KMAP_MAX_TIDS];
} KMAP_INJECT_REQ, *PKMAP_INJECT_REQ;

typedef struct _KMAP_IO_REQ
{
    ULONG   ProcessId;
    ULONG   Length;               // 上限 1 MB
    ULONG64 Address;
    UCHAR   Data[1];              // 变长
} KMAP_IO_REQ, *PKMAP_IO_REQ;

typedef struct _KMAP_BASE_REQ
{
    ULONG  ProcessId;
    WCHAR  ModuleName[64];
    ULONG64 Base;
    ULONG  ImageSize;
} KMAP_BASE_REQ, *PKMAP_BASE_REQ;

static PDEVICE_OBJECT g_DeviceObject = NULL;

/* 内核里没有 CRT 的 _stricmp/strlen，自己实现 */
static int KmapStricmpA(PCSTR a, PCSTR b)
{
    while (*a && *b)
    {
        CHAR ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (CHAR)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (CHAR)(cb + 32);
        if (ca != cb) return (int)ca - (int)cb;
        a++; b++;
    }
    return (int)(UCHAR)*a - (int)(UCHAR)*b;
}

static SIZE_T KmapStrlenA(PCSTR s)
{
    SIZE_T n = 0;
    while (s[n]) n++;
    return n;
}

/* ---------------------------------------------------------------- 基础工具 */

static NTSTATUS KmapReadFile(PCWSTR Path, PVOID* OutBuffer, SIZE_T* OutSize)
{
    UNICODE_STRING    us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK   iosb;
    HANDLE            hFile = NULL;
    FILE_STANDARD_INFORMATION fsi;
    NTSTATUS          st;
    PVOID             buf;
    LARGE_INTEGER     offset;

    *OutBuffer = NULL;
    *OutSize = 0;

    RtlInitUnicodeString(&us, Path);
    InitializeObjectAttributes(&oa, &us,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    st = ZwCreateFile(&hFile, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(st)) return st;

    st = ZwQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(st)) { ZwClose(hFile); return st; }
    if (fsi.EndOfFile.QuadPart <= 0 || fsi.EndOfFile.QuadPart > (64LL << 20))
    {
        ZwClose(hFile);
        return STATUS_FILE_TOO_LARGE;
    }

    buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)fsi.EndOfFile.QuadPart, KMAP_POOL);
    if (!buf) { ZwClose(hFile); return STATUS_INSUFFICIENT_RESOURCES; }

    offset.QuadPart = 0;
    st = ZwReadFile(hFile, NULL, NULL, NULL, &iosb, buf,
                    (ULONG)fsi.EndOfFile.QuadPart, &offset, NULL);
    ZwClose(hFile);
    if (!NT_SUCCESS(st)) { ExFreePoolWithTag(buf, KMAP_POOL); return st; }

    *OutBuffer = buf;
    *OutSize = (SIZE_T)fsi.EndOfFile.QuadPart;
    return STATUS_SUCCESS;
}

static ULONG64 AlignDown64(ULONG64 v, ULONG64 a) { return v & ~(a - 1); }
static ULONG64 AlignUp64(ULONG64 v, ULONG64 a)   { return (v + a - 1) & ~(a - 1); }

/* 目标进程内按模块名找基址（必须在 attach 之后调用）
 * 注意：内核态 GS 指向 KPCR，gs:[0x60] 是"用户态取 PEB"的写法，这里必须用
 * PsGetProcessPeb(PsGetCurrentProcess())。attach 之后 current 就是目标进程。 */
static PVOID TargetModuleBase(PCWSTR ModuleName)
{
    PVOID         peb;
    PKMAP_PEB_LDR ldr;
    LIST_ENTRY*   head;
    LIST_ENTRY*   cur;
    PVOID         result = NULL;
    UNICODE_STRING want;

    peb = PsGetProcessPeb(PsGetCurrentProcess());
    if (!peb) return NULL;

    __try
    {
        ldr = (PKMAP_PEB_LDR)(*(PVOID*)((PUCHAR)peb + KMAP_PEB_LDR_OFFSET));
        if (!ldr) return NULL;

        RtlInitUnicodeString(&want, ModuleName);
        head = &ldr->InLoadOrderModuleList;

        for (cur = head->Flink; cur != head && cur; cur = cur->Flink)
        {
            PKMAP_LDR_ENTRY e = CONTAINING_RECORD(cur, KMAP_LDR_ENTRY, InLoadOrderLinks);
            if (e->BaseDllName.Buffer && e->BaseDllName.Length &&
                RtlEqualUnicodeString(&e->BaseDllName, &want, TRUE))
            {
                result = e->DllBase;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[kmap] PEB walk faulted\n");
        result = NULL;
    }
    return result;
}

/* 本地（attach 后即目标地址空间）导出解析 */
static PVOID TargetGetProcAddress(PVOID ModuleBase, PCSTR FuncName)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ModuleBase;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_EXPORT_DIRECTORY exp;
    ULONG* names;
    USHORT* ords;
    ULONG* funcs;
    ULONG i;

    if (!ModuleBase || dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return NULL;

    exp   = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    names = (ULONG*)((PUCHAR)ModuleBase + exp->AddressOfNames);
    ords  = (USHORT*)((PUCHAR)ModuleBase + exp->AddressOfNameOrdinals);
    funcs = (ULONG*)((PUCHAR)ModuleBase + exp->AddressOfFunctions);

    if (exp->NumberOfNames > 0x10000) return NULL;

    for (i = 0; i < exp->NumberOfNames; i++)
    {
        PCSTR name = (PCSTR)((PUCHAR)ModuleBase + names[i]);
        if (KmapStricmpA(name, FuncName) == 0)
            return (PVOID)((PUCHAR)ModuleBase + funcs[ords[i]]);
    }
    return NULL;
}

/* ------------------------------------------------------------ PE 手动映射 */

static NTSTATUS ApplyRelocations(PUCHAR ImageBase, PIMAGE_NT_HEADERS Nt)
{
    ULONG64 delta = (ULONG64)ImageBase - Nt->OptionalHeader.ImageBase;
    PIMAGE_DATA_DIRECTORY dir;
    PIMAGE_BASE_RELOCATION rel;
    ULONG size, off;

    if (delta == 0) return STATUS_SUCCESS;
    dir = &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir->VirtualAddress || !dir->Size) return STATUS_SUCCESS;

    rel = (PIMAGE_BASE_RELOCATION)(ImageBase + dir->VirtualAddress);
    size = dir->Size;
    off = 0;

    while (off < size && rel->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
    {
        ULONG count = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        USHORT* item = (USHORT*)((PUCHAR)rel + sizeof(IMAGE_BASE_RELOCATION));
        ULONG i;

        for (i = 0; i < count; i++)
        {
            ULONG type = item[i] >> 12;
            ULONG rva  = item[i] & 0x0FFF;
            PUCHAR patch = ImageBase + rel->VirtualAddress + rva;

            if (type == IMAGE_REL_BASED_DIR64)       *(ULONG64*)patch += delta;
            else if (type == IMAGE_REL_BASED_HIGHLOW) *(ULONG32*)patch += (ULONG32)delta;
            /* IMAGE_REL_BASED_ABSOLUTE / HIGH / LOW 忽略 */
        }
        off += rel->SizeOfBlock;
        rel = (PIMAGE_BASE_RELOCATION)((PUCHAR)rel + rel->SizeOfBlock);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS ResolveImports(PUCHAR ImageBase, PIMAGE_NT_HEADERS Nt)
{
    PIMAGE_DATA_DIRECTORY dir;
    PIMAGE_IMPORT_DESCRIPTOR imp;
    ULONG off = 0;

    dir = &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir->VirtualAddress || !dir->Size) return STATUS_SUCCESS;

    imp = (PIMAGE_IMPORT_DESCRIPTOR)(ImageBase + dir->VirtualAddress);
    while (imp->Name && off < dir->Size)
    {
        PCSTR modName = (PCSTR)(ImageBase + imp->Name);
        WCHAR wide[128];
        PVOID modBase;
        ULONG i;

        if (KmapStrlenA(modName) >= 120) return STATUS_INVALID_IMAGE_FORMAT;
        for (i = 0; i <= KmapStrlenA(modName); i++) wide[i] = (WCHAR)modName[i];

        modBase = TargetModuleBase(wide);
        if (!modBase)
        {
            /* 不在已加载列表里：记录并跳过（宿主可预先加载，或用 delay-load） */
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[kmap] module not loaded: %s\n", modName);
            return STATUS_DLL_NOT_FOUND;
        }

        {
            PIMAGE_THUNK_DATA thunkIat = (PIMAGE_THUNK_DATA)(ImageBase + (imp->FirstThunk ? imp->FirstThunk : imp->OriginalFirstThunk));
            PIMAGE_THUNK_DATA thunkInt;
            if (!thunkIat) { imp++; off += sizeof(IMAGE_IMPORT_DESCRIPTOR); continue; }
            thunkInt = imp->OriginalFirstThunk
                     ? (PIMAGE_THUNK_DATA)(ImageBase + imp->OriginalFirstThunk)
                     : thunkIat;

            for (;;)
            {
                if (thunkInt->u1.AddressOfData == 0) break;

                if (thunkInt->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                {
                    /* 按序号导入：直接按 ordinal 取导出 */
                    ULONG ord = (ULONG)(thunkInt->u1.Ordinal & 0xFFFF);
                    PIMAGE_DOS_HEADER d2 = (PIMAGE_DOS_HEADER)modBase;
                    PIMAGE_NT_HEADERS n2 = (PIMAGE_NT_HEADERS)((PUCHAR)modBase + d2->e_lfanew);
                    PIMAGE_EXPORT_DIRECTORY e2 = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)modBase +
                        n2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                    ULONG* f2 = (ULONG*)((PUCHAR)modBase + e2->AddressOfFunctions);
                    thunkIat->u1.Function = (ULONG64)((PUCHAR)modBase + f2[ord - e2->Base]);
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(ImageBase + thunkInt->u1.AddressOfData);
                    PVOID fn = TargetGetProcAddress(modBase, (PCSTR)ibn->Name);
                    if (!fn) return STATUS_PROCEDURE_NOT_FOUND;
                    thunkIat->u1.Function = (ULONG64)fn;
                }
                thunkInt++;
                thunkIat++;
            }
        }
        imp++;
        off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS ProtectImageSections(PUCHAR ImageBase, PIMAGE_NT_HEADERS Nt)
{
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(Nt);
    ULONG i;

    for (i = 0; i < Nt->FileHeader.NumberOfSections; i++)
    {
        ULONG protect = PAGE_EXECUTE_READWRITE;
        ULONG size;
        PVOID base;
        SIZE_T region = 0;

        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            protect = (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            protect = PAGE_READWRITE;
        else
            protect = PAGE_READONLY;

        size   = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (!size) continue;

        base   = ImageBase + sec[i].VirtualAddress;
        region = size;
        ZwProtectVirtualMemory(NtCurrentProcess(), &base, &region, protect, NULL);
    }
    return STATUS_SUCCESS;
}

static VOID KmapApcKernelRoutine(PVOID Apc, KMAP_NORMAL_ROUTINE* NormalRoutine,
                                 PVOID* NormalContext, PVOID* SystemArgument1,
                                 PVOID* SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    if (Apc) ExFreePoolWithTag(Apc, KMAP_POOL);
}

/* 在目标里投放 APC 执行壳：调用 DllMain(hinst, DLL_PROCESS_ATTACH, NULL) */
static NTSTATUS QueueDllMain(PEPROCESS Process, PULONG ThreadIds, ULONG ThreadCount, PVOID ImageBase, PVOID EntryPoint, ULONG Flags, ULONG64* OutShell)
{
    /*
     *  48 83 EC 28              sub  rsp, 0x28
     *  48 B9 <hinst>            mov  rcx, hinst
     *  BA 01 00 00 00           mov  edx, 1
     *  45 31 C0                 xor  r8d, r8d
     *  48 B8 <entry>            mov  rax, entry
     *  FF D0                    call rax
     *  48 83 C4 28              add  rsp, 0x28
     *  C3                       ret
     */
    UCHAR  code[64];
    ULONG  n = 0;
    PVOID  shellVa = NULL;
    SIZE_T shellSize = 0x1000;
    NTSTATUS st;
    KAPC_STATE  apcState;
    ULONG  i;
    ULONG  queued = 0;

    KeStackAttachProcess(Process, &apcState);
    st = ZwAllocateVirtualMemory(NtCurrentProcess(), &shellVa, 0, &shellSize,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (NT_SUCCESS(st) && (Flags & KMAP_FLAG_PROBE))
    {
        /* 最小判据：只写哨兵然后死循环，不调用任何 API、不碰 CRT */
        ULONG64 sentinel = (ULONG64)shellVa + 0x800;
        UCHAR probe[32];
        ULONG k = 0;
        probe[k++] = 0x48; probe[k++] = 0xBA;
        *(ULONG64*)(probe + k) = sentinel; k += 8;
        probe[k++] = 0xC7; probe[k++] = 0x02; probe[k++] = 0xAA; probe[k++] = 0xAA;
        probe[k++] = 0xAA; probe[k++] = 0xAA;
        probe[k++] = 0xEB; probe[k++] = 0xFE;          /* jmp $ */
        RtlCopyMemory(shellVa, probe, k);
    }
    else if (NT_SUCCESS(st))
    {
        ULONG64 sentinel = (ULONG64)shellVa + 0x800;

        /*  48 83 EC 28              sub  rsp, 0x28
         *  48 BA <sentinel>         mov  rdx, sentinel
         *  C7 02 11 11 11 11        mov  dword [rdx], 0x11111111   ; 壳已开始
         *  48 B9 <hinst>            mov  rcx, hinst
         *  BA 01 00 00 00           mov  edx, 1
         *  45 31 C0                 xor  r8d, r8d
         *  48 B8 <entry>            mov  rax, entry
         *  FF D0                    call rax
         *  48 BA <sentinel>         mov  rdx, sentinel
         *  C7 02 22 22 22 22        mov  dword [rdx], 0x22222222   ; DllMain 正常返回
         *  48 83 C4 28              add  rsp, 0x28
         *  C3                       ret
         */
        code[n++] = 0x48; code[n++] = 0x83; code[n++] = 0xEC; code[n++] = 0x28;
        code[n++] = 0x48; code[n++] = 0xBA;
        *(ULONG64*)(code + n) = sentinel; n += 8;
        code[n++] = 0xC7; code[n++] = 0x02; code[n++] = 0x11; code[n++] = 0x11;
        code[n++] = 0x11; code[n++] = 0x11;
        code[n++] = 0x48; code[n++] = 0xB9;
        *(ULONG64*)(code + n) = (ULONG64)ImageBase; n += 8;
        code[n++] = 0xBA; code[n++] = 0x01; code[n++] = 0x00; code[n++] = 0x00; code[n++] = 0x00;
        code[n++] = 0x45; code[n++] = 0x31; code[n++] = 0xC0;
        code[n++] = 0x48; code[n++] = 0xB8;
        *(ULONG64*)(code + n) = (ULONG64)EntryPoint; n += 8;
        code[n++] = 0xFF; code[n++] = 0xD0;
        code[n++] = 0x48; code[n++] = 0xBA;
        *(ULONG64*)(code + n) = sentinel; n += 8;
        code[n++] = 0xC7; code[n++] = 0x02; code[n++] = 0x22; code[n++] = 0x22;
        code[n++] = 0x22; code[n++] = 0x22;
        code[n++] = 0x48; code[n++] = 0x83; code[n++] = 0xC4; code[n++] = 0x28;
        code[n++] = 0xC3;

        RtlCopyMemory(shellVa, code, n);
        /* 调试期保留 RWX（哨兵要写同页）；验证通过后可降成 RX */
    }
    KeUnstackDetachProcess(&apcState);
    if (!NT_SUCCESS(st)) return st;

    /* 方式 A：直接建用户线程（不依赖可告警等待） */
    if (OutShell) *OutShell = (ULONG64)shellVa;
    if ((Flags & KMAP_FLAG_NEW_THREAD) || (Flags & KMAP_FLAG_PROBE))
    {
        HANDLE   hThread = NULL;
        NTSTATUS st2;
        KeStackAttachProcess(Process, &apcState);
        st2 = RtlCreateUserThread((HANDLE)(LONG_PTR)-1, NULL, FALSE, 0,
                                  0x100000, 0x10000, shellVa, NULL,
                                  &hThread, NULL);
        KeUnstackDetachProcess(&apcState);
        if (hThread) ZwClose(hThread);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[kmap] RtlCreateUserThread = 0x%X\n", st2);
        return st2;
    }

    /* 方式 B：投递用户态 APC：用户 APC 只在线程"可告警等待"时被交付，
       所以对目标的所有线程各排一个，谁先进入可告警等待谁先跑 DllMain。 */
    if (!ThreadIds || !ThreadCount) return STATUS_INVALID_PARAMETER;

    queued = 0;
    for (i = 0; i < ThreadCount && i < KMAP_MAX_TIDS; i++)
    {
        PETHREAD t = NULL;
        PVOID    apc;

        if (!ThreadIds[i]) continue;
        if (!NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)ThreadIds[i], &t))) continue;
        if (IoThreadToProcess(t) != Process) { ObDereferenceObject(t); continue; }
        if (t == PsGetCurrentThread()) { ObDereferenceObject(t); continue; }

        apc = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x100, KMAP_POOL);
        if (!apc) { ObDereferenceObject(t); continue; }

        KeInitializeApc(apc, t, KMAP_APC_ENV_ORIGINAL,
                        (PVOID)KmapApcKernelRoutine, NULL,
                        shellVa, KMAP_MODE_USER, NULL);

        if (KeInsertQueueApc(apc, NULL, NULL, 0)) queued++;
        else ExFreePoolWithTag(apc, KMAP_POOL);

        ObDereferenceObject(t);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[kmap] apc queued=%lu\n", queued);
    return queued ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/* --------------------------------------------------------------- 注入主体 */

/* 走目标进程自己的 LoadLibraryW：由真正的 loader 完成导入/TLS/CRT/DllMain，
   不依赖手动映射（手动映射的模块不在 PEB->Ldr，CRT 初始化会卡住）。 */
static NTSTATUS KmapLoadLibrary(PEPROCESS Process, PCWSTR DllPath, ULONG64* OutBase)
{
    KAPC_STATE apcState;
    PVOID      k32, pLoad, strVa = NULL;
    SIZE_T     strSize;
    PCWSTR     plain = DllPath;
    HANDLE     hThread = NULL;
    NTSTATUS   st;

    /* 去掉 \??\ 前缀：LoadLibraryW 要 Win32 路径 */
    if (plain[0] == L'\\' && plain[1] == L'?' && plain[2] == L'?' && plain[3] == L'\\')
        plain += 4;

    strSize = (wcslen(plain) + 1) * sizeof(WCHAR);

    KeStackAttachProcess(Process, &apcState);
    k32 = TargetModuleBase(L"kernel32.dll");
    pLoad = k32 ? TargetGetProcAddress(k32, "LoadLibraryW") : NULL;
    if (pLoad)
        st = ZwAllocateVirtualMemory(NtCurrentProcess(), &strVa, 0, &strSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    else
        st = STATUS_PROCEDURE_NOT_FOUND;

    if (NT_SUCCESS(st))
    {
        RtlCopyMemory(strVa, plain, strSize);
        st = RtlCreateUserThread((HANDLE)(LONG_PTR)-1, NULL, FALSE, 0,
                                 0x100000, 0x10000, pLoad, strVa, &hThread, NULL);
    }
    KeUnstackDetachProcess(&apcState);

    if (hThread) ZwClose(hThread);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[kmap] LoadLibraryW=%p thread=0x%X\n", pLoad, st);

    if (!NT_SUCCESS(st)) return st;
    if (OutBase) *OutBase = (ULONG64)pLoad;
    return STATUS_SUCCESS;
}

static NTSTATUS KmapInjectDll(ULONG ProcessId, PULONG ThreadIds, ULONG ThreadCount, PCWSTR DllPath, ULONG Flags,
                              ULONG64* OutBase, ULONG64* OutShell)
{
    PEPROCESS   process = NULL;
    PVOID       fileBuf = NULL;
    SIZE_T      fileSize = 0;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    ULONG       imageSize;
    PVOID       imageBase = NULL;
    SIZE_T      region;
    KAPC_STATE       apcState;
    NTSTATUS    st;
    ULONG       i;

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(st)) return st;

    if (Flags & KMAP_FLAG_LOADLIB)
    {
        st = KmapLoadLibrary(process, DllPath, OutBase);
        ObDereferenceObject(process);
        return st;
    }

    st = KmapReadFile(DllPath, &fileBuf, &fileSize);
    if (!NT_SUCCESS(st)) { ObDereferenceObject(process); return st; }

    dos = (PIMAGE_DOS_HEADER)fileBuf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { st = STATUS_INVALID_IMAGE_FORMAT; goto done; }
    nt = (PIMAGE_NT_HEADERS)((PUCHAR)fileBuf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        st = STATUS_INVALID_IMAGE_FORMAT; goto done;
    }

    imageSize = nt->OptionalHeader.SizeOfImage;
    region    = imageSize;

    KeStackAttachProcess(process, &apcState);
    st = ZwAllocateVirtualMemory(NtCurrentProcess(), &imageBase, 0, &region,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(st)) { KeUnstackDetachProcess(&apcState); goto done; }

    RtlCopyMemory(imageBase, fileBuf, nt->OptionalHeader.SizeOfHeaders);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt) + i;
        if (!sec->SizeOfRawData) continue;
        RtlCopyMemory((PUCHAR)imageBase + sec->VirtualAddress,
                      (PUCHAR)fileBuf + sec->PointerToRawData,
                      sec->SizeOfRawData);
    }

    ApplyRelocations((PUCHAR)imageBase, nt);
    st = ResolveImports((PUCHAR)imageBase, nt);
    if (NT_SUCCESS(st))
        st = ProtectImageSections((PUCHAR)imageBase, nt);

    if (NT_SUCCESS(st) && !(Flags & 1))
        st = QueueDllMain(process, ThreadIds, ThreadCount, imageBase,
                          (PUCHAR)imageBase + nt->OptionalHeader.AddressOfEntryPoint, Flags, OutShell);

    KeUnstackDetachProcess(&apcState);

    if (NT_SUCCESS(st) && OutBase) *OutBase = (ULONG64)imageBase;

done:
    if (fileBuf) ExFreePoolWithTag(fileBuf, KMAP_POOL);
    ObDereferenceObject(process);
    return st;
}

/* ------------------------------------------------------------- 读写原语 */

static NTSTATUS KmapCopyMemory(ULONG ProcessId, ULONG64 Address, PVOID Buffer,
                               ULONG Length, BOOLEAN Write)
{
    PEPROCESS process = NULL;
    KAPC_STATE     apcState;
    NTSTATUS  st = STATUS_SUCCESS;

    if (Length == 0 || Length > (1 << 20)) return STATUS_INVALID_PARAMETER;

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(st)) return st;

    KeStackAttachProcess(process, &apcState);
    __try
    {
        if (Write)
        {
            PVOID  base = (PVOID)Address;
            SIZE_T region = Length;
            ZwProtectVirtualMemory(NtCurrentProcess(), &base, &region,
                                   PAGE_EXECUTE_READWRITE, NULL);
            RtlCopyMemory((PVOID)Address, Buffer, Length);
        }
        else
        {
            RtlCopyMemory(Buffer, (PVOID)Address, Length);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        st = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apcState);

    ObDereferenceObject(process);
    return st;
}

/* ------------------------------------------------------------- 驱动骨架 */

static NTSTATUS KmapCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS KmapDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG  code = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID  inBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG  inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG  outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
    ULONG info = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (code)
    {
    case KMAP_IOCTL_PING:
        st = STATUS_SUCCESS;
        break;

    case KMAP_IOCTL_INJECT:
        if (inLen >= sizeof(KMAP_INJECT_REQ) && outLen >= sizeof(ULONG64) * 2)
        {
            PKMAP_INJECT_REQ req = (PKMAP_INJECT_REQ)inBuf;
            ULONG64 base = 0, shell = 0;
            req->DllPath[RTL_NUMBER_OF(req->DllPath) - 1] = 0;
            st = KmapInjectDll(req->ProcessId,
                               req->ThreadCount ? req->ThreadIds : &req->ThreadId,
                               req->ThreadCount, req->DllPath, req->Flags, &base, &shell);
            ((ULONG64*)inBuf)[0] = base;
            ((ULONG64*)inBuf)[1] = shell;
            info = sizeof(ULONG64) * 2;
        }
        else st = STATUS_BUFFER_TOO_SMALL;
        break;

    case KMAP_IOCTL_READ:
    case KMAP_IOCTL_WRITE:
        if (inLen >= sizeof(KMAP_IO_REQ) && (code == KMAP_IOCTL_WRITE ? outLen >= sizeof(KMAP_IO_REQ) : TRUE))
        {
            PKMAP_IO_REQ req = (PKMAP_IO_REQ)inBuf;
            if (req->Length && req->Length <= (1 << 20) &&
                inLen >= sizeof(KMAP_IO_REQ) + req->Length)
            {
                if (code == KMAP_IOCTL_WRITE)
                {
                    st = KmapCopyMemory(req->ProcessId, req->Address, req->Data, req->Length, TRUE);
                    info = 0;
                }
                else
                {
                    st = KmapCopyMemory(req->ProcessId, req->Address, req->Data, req->Length, FALSE);
                    /* METHOD_BUFFERED 只回传 Information 字节：必须把 Data 的偏移算进去，
                       否则用户态拿到的永远是结构体头部的旧值（表现为"读出来全是 0"） */
                    info = (ULONG)(FIELD_OFFSET(KMAP_IO_REQ, Data) + req->Length);
                }
            }
            else st = STATUS_INVALID_PARAMETER;
        }
        else st = STATUS_BUFFER_TOO_SMALL;
        break;

    case KMAP_IOCTL_GETBASE:
        if (inLen >= sizeof(KMAP_BASE_REQ) && outLen >= sizeof(KMAP_BASE_REQ))
        {
            PKMAP_BASE_REQ req = (PKMAP_BASE_REQ)inBuf;
            PEPROCESS process = NULL;
            KAPC_STATE apcState;
            req->ModuleName[63] = 0;
            st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &process);
            if (NT_SUCCESS(st))
            {
                KeStackAttachProcess(process, &apcState);
                req->Base = (ULONG64)TargetModuleBase(req->ModuleName);
                req->ImageSize = 0;
                KeUnstackDetachProcess(&apcState);
                ObDereferenceObject(process);
                info = sizeof(KMAP_BASE_REQ);
            }
        }
        else st = STATUS_BUFFER_TOO_SMALL;
        break;

    default:
        break;
    }

    Irp->IoStatus.Status = st;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return st;
}

static VOID KmapUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING link;
    RtlInitUnicodeString(&link, KMAP_LINK);
    IoDeleteSymbolicLink(&link);
    if (g_DeviceObject) IoDeleteDevice(g_DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING  devName, linkName;
    NTSTATUS        st;
    PDEVICE_OBJECT  dev = NULL;
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&devName, KMAP_DEVICE);
    st = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                        FILE_DEVICE_SECURE_OPEN, FALSE, &dev);
    if (!NT_SUCCESS(st)) return st;
    g_DeviceObject = dev;

    RtlInitUnicodeString(&linkName, KMAP_LINK);
    st = IoCreateSymbolicLink(&linkName, &devName);
    if (!NT_SUCCESS(st))
    {
        IoDeleteDevice(dev);
        g_DeviceObject = NULL;
        return st;
    }

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = KmapCreateClose;

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KmapDeviceControl;
    DriverObject->DriverUnload = KmapUnload;

    dev->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[kmap] loaded\n");
    return STATUS_SUCCESS;
}

