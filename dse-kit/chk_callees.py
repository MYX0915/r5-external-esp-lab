import sys, struct
sys.path.insert(0,'.')
import kva
k = kva.KVA(); base,size = kva.nt_base()
targets = [0x9477B0, 0x9480D0, 0x943FFD0]
for rva in targets:
    d = k.read(base+rva, 24)
    pat = ''
    if d[0]==0xE9:
        t = base+rva+5+struct.unpack_from('<i',d,1)[0]
        pat = f'  *** E9 -> 0x{t:X}'
    elif d[0]==0x48 and d[1]==0xB8 and d[10]==0xFF and d[11]==0xE0:
        t = struct.unpack_from('<Q',d,2)[0]
        pat = f'  *** MOVJMP -> 0x{t:X}'
    elif d[0]==0xFF and d[1]==0x25:
        pat = '  *** FF25'
    print(f"  rva=0x{rva:X}  {d.hex(' ')}{pat}")
