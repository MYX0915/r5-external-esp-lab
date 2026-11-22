import numpy as np, os
D=r"C:\ProgramData\scdump"
a=np.fromfile(os.path.join(D,"1_mod1.bin"),dtype=np.float32)
b=np.fromfile(os.path.join(D,"2_mod1.bin"),dtype=np.float32)
n=min(len(a),len(b)); a=a[:n]; b=b[:n]

def show(off, label):
    w1=a[off//4:off//4+16]; w2=b[off//4:off//4+16]
    if len(w1)<16: return
    print(f"--- {label} 0x{off:08X} ---")
    for r in range(4):
        print("   p1: " + " ".join(f"{w1[r*4+c]:9.4f}" for c in range(4)))
        print("   p2: " + " ".join(f"{w2[r*4+c]:9.4f}" for c in range(4)))
        print()

# scan the hot pages for 16-float windows that look like a 3x4/4x4 transform
for base in (0x00B80000, 0x00B81000, 0x00B82000, 0x020AE000, 0x00436000):
    win1 = a[base//4: base//4 + 4096//4]
    win2 = b[base//4: base//4 + 4096//4]
    best=[]
    for i in range(0, len(win1)-16):
        w1=win1[i:i+16]; w2=win2[i:i+16]
        if not (np.isfinite(w1).all() and np.isfinite(w2).all()): continue
        if np.abs(w1).max() > 100 or np.abs(w2).max() > 100: continue
        ch=int((w1!=w2).sum())
        if ch < 4: continue
        # rotation-ish: upper 3x3 entries <= 1.5
        r3=np.abs(w1[:3]).max(); r7=np.abs(w1[4:7]).max(); r11=np.abs(w1[8:11]).max()
        if max(r3,r7,r11) > 2.0: continue
        best.append((ch, i*4, w1.copy(), w2.copy()))
    best.sort(key=lambda x:-x[0])
    print(f"### page 0x{base:08X}: {len(best)} candidates")
    for ch, off, w1, w2 in best[:2]:
        print(f"  cand off=0x{base+off:08X} changed={ch}")
        for r in range(4):
            print("     " + " ".join(f"{w1[r*4+c]:9.4f}" for c in range(4)))
