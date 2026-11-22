"""hookcheck.py -- 检查游戏进程内 ntdll/kernel32/kernelbase 的关键 API 是否被 hook

方法：从内存镜像的导出表定位 API 的 RVA，取出前 24 字节；
      与磁盘文件同一 RVA 的字节比较。
      若不同且以 E9/E8/48B8..FFE0/FF25 开头 -> 判定为 hook，并解出跳转目标。
"""
import os
import struct

TARGETS = [
    ('udll_ntdll.dll.bin',      r'C:\Windows\System32\ntdll.dll',
     ['NtAllocateVirtualMemory', 'NtProtectVirtualMemory', 'NtCreateThreadEx',
      'NtCreateThread', 'NtMapViewOfSection', 'NtCreateSection', 'LdrLoadDll',
      'LdrGetProcedureAddress', 'NtQueueApcThread', 'NtSetContextThread',
      'NtGetContextThread', 'NtWriteVirtualMemory', 'NtReadVirtualMemory']),
    ('udll_kernel32.dll.bin',   r'C:\Windows\System32\kernel32.dll',
     ['LoadLibraryW', 'LoadLibraryExW', 'VirtualAlloc', 'VirtualProtect',
      'CreateThread', 'CreateRemoteThread', 'GetProcAddress']),
    ('udll_kernelbase.dll.bin', r'C:\Windows\System32\kernelbase.dll',
     ['VirtualAlloc', 'VirtualProtect', 'CreateThread', 'LoadLibraryExW',
      'CreateRemoteThreadEx', 'GetProcAddress']),
]


def parse(d):
    e = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, e + 6)[0]
    optsz = struct.unpack_from('<H', d, e + 20)[0]
    opt = e + 24
    secs = []
    so = opt + optsz
    for i in range(nsec):
        s = so + i * 40
        nm = d[s:s + 8].rstrip(b'\0').decode('latin1', 'ignore')
        vs, va, rs, rp = struct.unpack_from('<IIII', d, s + 8)
        secs.append((nm, va, vs, rp, rs))
    exp_rva, exp_sz = struct.unpack_from('<II', d, opt + 0x70)
    return secs, exp_rva, exp_sz


def r2o(secs, rva):
    for nm, va, vs, rp, rs in secs:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None


def exports(d, secs, exp_rva, exp_sz):
    out = {}
    if exp_rva == 0:
        return out
    try:
        nn = struct.unpack_from('<I', d, exp_rva + 0x18)[0]
        af, an, ao = struct.unpack_from('<III', d, exp_rva + 0x1C)
    except struct.error:
        return out
    for i in range(min(nn, 8000)):
        try:
            nr = struct.unpack_from('<I', d, an + i * 4)[0]
            end = d.find(b'\0', nr, nr + 128)
            nm = d[nr:end].decode('latin1', 'ignore')
            oi = struct.unpack_from('<H', d, ao + i * 2)[0]
            fr = struct.unpack_from('<I', d, af + oi * 4)[0]
            out[nm] = fr
        except Exception:
            continue
    return out


def describe(b):
    if len(b) >= 12 and b[0] == 0x48 and b[1] == 0xB8 and b[10] == 0xFF and b[11] == 0xE0:
        return 'MOV RAX,imm64; JMP RAX'
    if len(b) >= 5 and b[0] == 0xE9:
        return 'JMP rel32'
    if len(b) >= 5 and b[0] == 0xE8:
        return 'CALL rel32'
    if len(b) >= 6 and b[0] == 0xFF and b[1] == 0x25:
        return 'JMP [rip+x]'
    if len(b) >= 2 and b[0] == 0xEB:
        return 'JMP rel8'
    return ''


for memname, diskpath, apis in TARGETS:
    mp = os.path.join(r'C:\ProgramData', memname)
    if not os.path.exists(mp) or not os.path.exists(diskpath):
        print(f"skip {memname}")
        continue
    mem = open(mp, 'rb').read()
    dsk = open(diskpath, 'rb').read()
    ms, mexp, mexp_sz = parse(mem)
    ds, dexp, dexp_sz = parse(dsk)
    me = exports(mem, ms, mexp, mexp_sz)
    de = exports(dsk, ds, dexp, dexp_sz)

    print(f"\n=== {memname} (内存 {len(mem):#x} / 磁盘 {len(dsk):#x}) ===")
    for api in apis:
        if api not in me or api not in de:
            continue
        mrva, drva = me[api], de[api]
        mo = r2o(ms, mrva)
        do = r2o(ds, drva)
        if mo is None or do is None:
            continue
        mb = mem[mo:mo + 24]
        db = dsk[do:do + 24]
        if mb == db:
            print(f"   {api:<26} OK      相同  {mb[:12].hex(' ')}")
        else:
            tag = describe(mb)
            print(f"   {api:<26} DIFF    mem={mb[:12].hex(' ')}  disk={db[:12].hex(' ')}  {tag}")
            if mb[0] == 0xE9 and len(mb) >= 5:
                rel = struct.unpack_from('<i', mb, 1)[0]
                print(f"        -> 目标 rva 0x{(mrva + 5 + rel) & 0xFFFFFFFF:X}")
            if mb[0] == 0x48 and mb[1] == 0xB8:
                v = struct.unpack_from('<Q', mb, 2)[0]
                print(f"        -> 目标 0x{v:X}")
