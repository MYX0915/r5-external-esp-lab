import sys, struct
sys.path.insert(0,'.')
import kva
k = kva.KVA(); base, size = kva.nt_base()
img = k.read(base, size)
print(f"ntoskrnl 0x{base:X} size=0x{size:X} read={len(img)}")
def outside(a): return not (base <= a < base+size)
hits=[]
# 1) E9 rel32
i=0
while True:
    i = img.find(b'\xe9', i)
    if i<0: break
    if i+5<=len(img):
        rel = struct.unpack_from('<i', img, i+1)[0]
        tgt = base + i + 5 + rel
        if outside(tgt): hits.append(('E9', i, tgt))
    i+=1
# 2) 48 B8 imm64 FF E0
i=0
while True:
    i = img.find(b'\x48\xb8', i)
    if i<0: break
    if i+12<=len(img) and img[i+10]==0xFF and img[i+11]==0xE0:
        tgt = struct.unpack_from('<Q', img, i+2)[0]
        if outside(tgt): hits.append(('MOVJMP', i, tgt))
    i+=1
# 3) FF 25 disp32 -> 指向外部的地址
i=0
while True:
    i = img.find(b'\xff\x25', i)
    if i<0: break
    if i+6<=len(img):
        disp = struct.unpack_from('<i', img, i+2)[0]
        slot = base + i + 6 + disp
        if not outside(slot):
            p = k.read(slot, 8)
            if p:
                tgt = struct.unpack('<Q', p)[0]
                if outside(tgt): hits.append(('FF25', i, tgt))
    i+=1
print(f"total hits={len(hits)}")
for kind, off, tgt in hits[:25]:
    print(f"  {kind:<7} rva=0x{off:<8X} -> 0x{tgt:X}")
