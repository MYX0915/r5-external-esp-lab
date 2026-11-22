import struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def load(path):
    d = open(path, 'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    coff = e + 4
    nsec = struct.unpack_from('<H', d, coff + 2)[0]
    optsize = struct.unpack_from('<H', d, coff + 16)[0]
    opt = coff + 20
    pe64 = struct.unpack_from('<H', d, opt)[0] == 0x20b
    base = struct.unpack_from('<Q', d, opt + 24)[0] if pe64 else struct.unpack_from('<I', d, opt + 28)[0]
    so = opt + optsize
    secs = []
    for i in range(nsec):
        s = so + i * 40
        name = d[s:s+8].rstrip(b'\0').decode('latin1')
        vs, va, rs, rp = struct.unpack_from('<IIII', d, s + 8)
        secs.append((name, va, vs, rp, rs))
    return d, base, secs

def rva2off(secs, rva):
    for name, va, vs, rp, rs in secs:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None

path = sys.argv[1]
d, base, secs = load(path)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

specs = sys.argv[2:]
for spec in specs:
    rva_s, ln_s = spec.split(':')
    rva = int(rva_s, 16)
    ln = int(ln_s, 16)
    off = rva2off(secs, rva)
    code = d[off:off + ln]
    print(f'=== RVA 0x{rva:X} (VA 0x{base+rva:X}) len 0x{ln:X} ===')
    print('bytes:', code.hex(' ').upper())
    for ins in md.disasm(code, base + rva):
        print(f'  0x{ins.address - base:08X}  {ins.bytes.hex().ljust(24)} {ins.mnemonic} {ins.op_str}')
    print()
