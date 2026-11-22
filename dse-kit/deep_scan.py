import glob, os, struct
KEY = [b'ObRegisterCallbacks', b'PsSetCreateThreadNotifyRoutine', b'PsSetLoadImageNotifyRoutine',
       b'MmCopyMemory', b'NtAllocateVirtualMemory', b'NtProtectVirtualMemory', b'PspCreateThread',
       b'eaac', b'javelin', b'Electronic Arts', b'EAAnti', b'MmCopyVirtualMemory', b'KeStackAttachProcess',
       b'\\Device\\', b'\\Driver\\', b'.grfn', b'themida', b'vmprotect']
for f in sorted(glob.glob(r'C:\ProgramData\kmod_FFFFF80366C*.bin')):
    d = open(f,'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    coff = e+4
    nsec = struct.unpack_from('<H', d, coff+2)[0]
    optsz = struct.unpack_from('<H', d, coff+16)[0]
    opt = coff+20
    ep = struct.unpack_from('<I', d, opt+16)[0]
    size_img = struct.unpack_from('<I', d, opt+56)[0]
    hits = [k.decode() for k in KEY if k in d]
    # 可见字符串统计（>=6 可打印）
    printable = 0; i = 0
    while i < len(d)-6:
        if 32 <= d[i] < 127:
            j = i
            while j < len(d) and 32 <= d[j] < 127: j += 1
            if j-i >= 6: printable += 1
            i = j
        else: i += 1
    print(f"{os.path.basename(f)}  img=0x{size_img:<7X} ep=0x{ep:<6X} nsec={nsec} strings~{printable}")
    if hits: print("    HITS:", ', '.join(hits))
