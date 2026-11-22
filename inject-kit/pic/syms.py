import struct
d = open(r'wnd.obj','rb').read()
ptr, n = struct.unpack_from('<II', d, 8)
strtab = ptr + n*18
out = []
for i in range(n):
    b = ptr + i*18
    name = d[b:b+8]
    val, sec, typ, cls, naux = struct.unpack_from('<IhHBB', d, b+8)
    if sec != 1:
        continue
    if name[:1] == b'\0':
        so = struct.unpack_from('<I', name, 4)[0]
        s = d[strtab+so:]
        nm = s[:s.index(b'\0')].decode('ascii','replace')
    else:
        nm = name.rstrip(b'\0').decode('ascii','replace')
    out.append(f'text sym {nm} = 0x{val:X}')
open('syms.txt','w',encoding='ascii').write('\n'.join(out))
