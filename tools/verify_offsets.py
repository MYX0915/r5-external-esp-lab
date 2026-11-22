import struct, sys

path = sys.argv[1]
d = open(path, 'rb').read()
e = struct.unpack_from('<I', d, 0x3C)[0]
coff = e + 4
n = struct.unpack_from('<H', d, coff + 2)[0]
os_ = struct.unpack_from('<H', d, coff + 16)[0]
opt = coff + 20
so = opt + os_
secs = []
for i in range(n):
    s = so + i * 40
    name = d[s:s+8].rstrip(b'\0').decode('latin1')
    vs, va, rs, rp = struct.unpack_from('<IIII', d, s + 8)
    secs.append((name, va, vs, rp, rs))

def r2o(rva):
    for name, va, vs, rp, rs in secs:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va), name
    return None, None

print('image base 0x%X' % struct.unpack_from('<Q', d, opt + 24)[0])
checks = [
    ('inventory_accessor @0x22CBD30', 0x22CBD30, 8, '48 8D 81 58 19 00 00 C3'),
    ('local_player_handle @0x3D3DCD0', 0x3D3DCD0, 8, None),
    ('entity_array @0x6B515D8', 0x6B515D8, 32, None),
]
for label, rva, ln, exp in checks:
    o, sec = r2o(rva)
    if o is None:
        print(f'{label}: NOT MAPPED'); continue
    b = d[o:o+ln]
    got = ' '.join(f'{x:02X}' for x in b)
    verdict = '' if exp is None else ('  <= MATCH' if got.upper() == exp.upper() else f'  <= MISMATCH expect {exp}')
    print(f'{label}: [{sec}] {got}{verdict}')
