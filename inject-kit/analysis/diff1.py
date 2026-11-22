import numpy as np, os
D=r"C:\ProgramData\scdump"
for tag in ("mod0","mod1"):
    a=np.fromfile(os.path.join(D,f"1_{tag}.bin"),dtype=np.uint8)
    b=np.fromfile(os.path.join(D,f"2_{tag}.bin"),dtype=np.uint8)
    n=min(len(a),len(b)); a=a[:n]; b=b[:n]
    diff = (a!=b)
    print(f"=== {tag}: {n/1048576:.1f} MB, changed bytes={diff.sum()} ({100.0*diff.sum()/n:.3f}%) ===")
    # group changed offsets into 4KB pages
    pages = np.nonzero(diff)[0] // 4096
    up, cnt = np.unique(pages, return_counts=True)
    order = np.argsort(-cnt)[:8]
    for i in order:
        print(f"   page 0x{up[i]*4096:08X}  changed={cnt[i]}")
