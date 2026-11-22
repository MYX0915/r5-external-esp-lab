import numpy as np, os
D=r"C:\ProgramData\scdump"
raw1=np.fromfile(os.path.join(D,"1_mod1.bin"),dtype=np.uint8)
raw2=np.fromfile(os.path.join(D,"2_mod1.bin"),dtype=np.uint8)
n=min(len(raw1),len(raw2)); raw1=raw1[:n]; raw2=raw2[:n]
a=raw1.view(np.float32); b=raw2.view(np.float32)
q1=raw1.view(np.uint64); q2=raw2.view(np.uint64)

print("=== 1) float ???????????????? ===")
cnt=0
for i in range(0, len(a)-3):
    v1=a[i:i+3]; v2=b[i:i+3]
    if not (np.isfinite(v1).all() and np.isfinite(v2).all()): continue
    if np.abs(v1).max()>20000 or np.abs(v2).max()>20000: continue
    if np.abs(v1).min()<1.0: continue
    ch=int((v1!=v2).sum())
    if ch<2: continue
    if len(set(np.round(v1,3)))<3: continue
    print(f"  off=0x{i*4:08X} p1=({v1[0]:.2f},{v1[1]:.2f},{v1[2]:.2f}) p2=({v2[0]:.2f},{v2[1]:.2f},{v2[2]:.2f})")
    cnt+=1
    if cnt>=12: break
print(f"  total shown={cnt}")

print()
print("=== 2) .data ??????????????? ===")
ptr=0; shown=0
for i in range(0, len(q1)):
    v=int(q1[i])
    if 0x10000000 <= v <= 0x7FFF00000000 and (v & 7)==0:
        # ????????"????"??? 4 ??????
        if i+4 <= len(q1)-1:
            nxt=[int(q1[i+k]) for k in range(1,4)]
            if all(0x10000000 <= x <= 0x7FFF00000000 and (x&7)==0 for x in nxt):
                if shown < 8:
                    print(f"  off=0x{i*8:08X} -> 0x{v:X}, 0x{nxt[0]:X}, 0x{nxt[1]:X}, 0x{nxt[2]:X}")
                    shown+=1
                ptr+=1
print(f"  pointer-array candidates={ptr}")
