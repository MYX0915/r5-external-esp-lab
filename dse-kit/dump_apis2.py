import sys, struct
sys.path.insert(0,'.')
import kva
k = kva.KVA(); base, size = kva.nt_base()
hdr = k.read(base, 0x1000)
e = struct.unpack_from('<I', hdr, 0x3C)[0]
nt = hdr[e:]
exp_rva, exp_sz = struct.unpack_from('<II', nt, 0x18 + 0x70)
d = k.read(base + exp_rva, 0x200)
nfuncs = struct.unpack_from('<I', d, 0x14)[0]
nnames = struct.unpack_from('<I', d, 0x18)[0]
addr_funcs, addr_names, addr_ords = struct.unpack_from('<III', d, 0x1C)
print(f"funcs={nfuncs} names={nnames} funcs_rva=0x{addr_funcs:X} names_rva=0x{addr_names:X}")
names = k.read(base + addr_names, nnames*4)
funcs = k.read(base + addr_funcs, nfuncs*4)
ords  = k.read(base + addr_ords, nnames*2)
want = {b'NtAllocateVirtualMemory', b'NtProtectVirtualMemory', b'NtCreateThreadEx',
        b'NtCreateUserProcess', b'MmCopyMemory', b'PsLookupProcessByProcessId'}
found = {}
for i in range(nnames):
    nrva = struct.unpack_from('<I', names, i*4)[0]
    nm = k.read(base + nrva, 64)
    if not nm: continue
    nm = nm.split(b'\0')[0]
    if nm in want:
        oi = struct.unpack_from('<H', ords, i*2)[0]
        frva = struct.unpack_from('<I', funcs, oi*4)[0]
        found[nm] = frva
for nm, rva in found.items():
    code = k.read(base + rva, 24)
    print(f"  {nm.decode():<26} rva=0x{rva:<8X} {code.hex(' ')}")
