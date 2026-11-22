import sys, struct
sys.path.insert(0,'.')
import kva
k = kva.KVA(); base, size = kva.nt_base()
hdr = k.read(base, 0x1000)
e = struct.unpack_from('<I', hdr, 0x3C)[0]
nt = hdr[e:]
magic = struct.unpack_from('<H', nt, 0x18)[0]
exp_rva, exp_sz = struct.unpack_from('<II', nt, 0x18 + 0x70)   # DataDirectory[0]
print(f"base=0x{base:X} e_lfanew=0x{e:X} magic=0x{magic:X} exp_rva=0x{exp_rva:X} size=0x{exp_sz:X}")
d = k.read(base + exp_rva, exp_sz)
nnames, nfuncs = struct.unpack_from('<II', d, 0x18)
addr_names, addr_funcs, addr_ords = struct.unpack_from('<III', d, 0x20)
print(f"names={nnames} funcs={nfuncs}")
names = k.read(base + addr_names, nnames*4)
funcs = k.read(base + addr_funcs, nfuncs*4)
ords  = k.read(base + addr_ords, nnames*2)
want = {b'NtAllocateVirtualMemory', b'NtProtectVirtualMemory', b'NtCreateThreadEx', b'MmCopyMemory'}
for i in range(nnames):
    nrva = struct.unpack_from('<I', names, i*4)[0]
    nm = k.read(base + nrva, 64)
    if not nm: continue
    nm = nm.split(b'\0')[0]
    if nm in want:
        oi = struct.unpack_from('<H', ords, i*2)[0]
        frva = struct.unpack_from('<I', funcs, oi*4)[0]
        code = k.read(base + frva, 24)
        print(f"  {nm.decode():<26} rva=0x{frva:<8X} bytes={code.hex(' ')}")
