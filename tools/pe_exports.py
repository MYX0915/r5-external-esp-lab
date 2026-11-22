import struct, sys, os

def parse(path):
    d = open(path, 'rb').read()
    e_lfanew = struct.unpack_from('<I', d, 0x3C)[0]
    assert d[e_lfanew:e_lfanew+4] == b'PE\0\0'
    coff = e_lfanew + 4
    nsec = struct.unpack_from('<H', d, coff + 2)[0]
    optsize = struct.unpack_from('<H', d, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from('<H', d, opt)[0]
    pe64 = magic == 0x20b
    img_base = struct.unpack_from('<Q', d, opt + 24)[0] if pe64 else struct.unpack_from('<I', d, opt + 28)[0]
    dd = opt + (112 if pe64 else 96)
    exp_rva, exp_size = struct.unpack_from('<II', d, dd)
    secs = []
    so = opt + optsize
    for i in range(nsec):
        s = so + i * 40
        name = d[s:s+8].rstrip(b'\0').decode('latin1')
        vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', d, s + 8)
        secs.append((name, vaddr, vsize, rawptr, rawsize))
    def rva2off(rva):
        for name, va, vs, rp, rs in secs:
            if va <= rva < va + max(vs, rs):
                return rp + (rva - va)
        return None
    eo = rva2off(exp_rva)
    nnames = struct.unpack_from('<I', d, eo + 24)[0]
    names_rva = struct.unpack_from('<I', d, eo + 32)[0]
    funcs_rva = struct.unpack_from('<I', d, eo + 28)[0]
    ords_rva = struct.unpack_from('<I', d, eo + 36)[0]
    no = rva2off(names_rva); fo = rva2off(funcs_rva); oo = rva2off(ords_rva)
    out = {}
    for i in range(nnames):
        nr = struct.unpack_from('<I', d, no + 4*i)[0]
        p = rva2off(nr)
        end = d.index(b'\0', p)
        nm = d[p:end].decode('latin1')
        oi = struct.unpack_from('<H', d, oo + 2*i)[0]
        fr = struct.unpack_from('<I', d, fo + 4*oi)[0]
        out[nm] = fr
    return d, img_base, secs, rva2off, out

for path in sys.argv[1:]:
    if not os.path.exists(path):
        print(f'{path}: missing'); continue
    d, base, secs, rva2off, exp = parse(path)
    print(f'== {os.path.basename(path)}  imagebase=0x{base:X}  exports={len(exp)}')
    for fn in ('MmCopyMemory', 'MmCopyVirtualMemory', 'KeStackAttachProcess', 'MmGetPhysicalAddress', 'PsGetProcessId'):
        if fn in exp:
            rva = exp[fn]
            off = rva2off(rva)
            b = d[off:off+16]
            print(f'  {fn:<24} RVA=0x{rva:08X}  VA=0x{base+rva:X}  bytes={b.hex(" ").upper()}')
