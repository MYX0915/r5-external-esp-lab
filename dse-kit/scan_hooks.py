import sys, struct
sys.path.insert(0,'.')
import kva
k = kva.KVA(); base, size = kva.nt_base()
print(f"ntoskrnl=0x{base:X} size=0x{size:X}")
img = k.read(base, size)
print("read image:", "OK" if img else "FAIL", len(img) if img else 0)
if not img: sys.exit(1)
hits=[]
pat = b'\x48\xB8'
i = 0
while True:
    i = img.find(pat, i)
    if i < 0: break
    if i+12 <= len(img) and img[i+10]==0xFF and img[i+11]==0xE0:
        tgt = struct.unpack_from('<Q', img, i+2)[0]
        # 目标在 ntoskrnl 之外的内核地址才算
        if not (base <= tgt < base+size):
            hits.append((i, tgt))
    i += 1
print(f"candidate jumps: {len(hits)}")
for off, tgt in hits[:30]:
    print(f"  rva=0x{off:X}  ->  0x{tgt:X}")
