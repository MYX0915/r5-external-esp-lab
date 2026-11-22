import sys, time
sys.path.insert(0,'.')
import kva
k = kva.KVA(); b,_ = kva.nt_base()
va = b + kva.MMCOPY_RVA
print(f"ntoskrnl=0x{b:X} MmCopyMemory=0x{va:X}")
seen = set()
for i in range(40):
    d = k.read(va, 16)
    if not d:
        print("read fail"); break
    sig = d.hex(' ')
    if d[0]==0x48 and d[1]==0xB8 and d[10]==0xFF and d[11]==0xE0:
        h = int.from_bytes(d[2:10],'little')
        print(f"[{i*0.5:.1f}s] HOOK -> handler=0x{h:X}")
    else:
        print(f"[{i*0.5:.1f}s] {sig}")
    time.sleep(0.5)
