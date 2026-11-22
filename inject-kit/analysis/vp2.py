import numpy as np, os
D=r"C:\ProgramData\scdump"
names=["h1_B7640000.bin","h2_5D970000.bin","h4_54860000.bin","h7_B4B00000.bin","h0_4F7B0000.bin","h8_4D730000.bin"]
best=[]
for name in names:
    p1=os.path.join(D,"1_"+name); p2=os.path.join(D,"2_"+name)
    if not (os.path.exists(p1) and os.path.exists(p2)): continue
    a=np.fromfile(p1,dtype=np.float32); b=np.fromfile(p2,dtype=np.float32)
    n=min(len(a),len(b)); a=a[:n]; b=b[:n]
    W=np.lib.stride_tricks.sliding_window_view(a,16)
    W2=np.lib.stride_tricks.sliding_window_view(b,16)
    # last row ~ (0,0,0,1)
    m = (np.abs(W[:,12])<1e-3)&(np.abs(W[:,13])<1e-3)&(np.abs(W[:,14])<1e-3)&(np.abs(W[:,15]-1.0)<1e-3)
    idx=np.nonzero(m)[0]
    for off in idx:
        w=W[off]
        if not np.isfinite(w).all(): continue
        if np.abs(w).max()>30000: continue
        rows=[np.linalg.norm(w[0:3]), np.linalg.norm(w[4:7]), np.linalg.norm(w[8:11])]
        if not all(0.8<r<1.2 for r in rows): continue
        ch=int((W[off]!=W2[off]).sum())
        best.append((ch, name, off*4, w.copy()))
best.sort(key=lambda x:-x[0])
print("matrix candidates:", len(best))
for ch,name,off,w in best[:8]:
    print(f"--- {name} +0x{off:08X} changed={ch}")
    for r in range(4):
        print("      " + " ".join(f"{w[r*4+c]:10.4f}" for c in range(4)))
