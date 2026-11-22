"""find candidate view matrices: 16 consecutive float32 that changed between two dumps
and look like a view-projection matrix."""
import mmap, os, re, struct, sys
import numpy as np

DUMP = r'C:\ProgramData\scdump'
LOG = r'C:\ProgramData\kmaplog.txt'

def manifest():
    ent = {}
    with open(LOG, 'r', errors='ignore') as f:
        for line in f:
            m = re.search(r'^p([12]) va=0x([0-9A-Fa-f]+) size=0x([0-9A-Fa-f]+) idx=(\d+)', line)
            if not m:
                continue
            p, va, sz, idx = int(m.group(1)), int(m.group(2), 16), int(m.group(3), 16), int(m.group(4))
            ent.setdefault((p, idx), (va, sz))
    return ent

def load_pair(idx, va):
    a = os.path.join(DUMP, f'1{idx}_{va:08X}.bin')
    b = os.path.join(DUMP, f'2{idx}_{va:08X}.bin')
    if not (os.path.exists(a) and os.path.exists(b)):
        return None, None
    x = np.fromfile(a, dtype=np.float32)
    y = np.fromfile(b, dtype=np.float32)
    n = min(len(x), len(y))
    return x[:n], y[:n]

def score_window(w1, w2):
    if not np.all(np.isfinite(w1)) or not np.all(np.isfinite(w2)):
        return -1
    if np.max(np.abs(w1)) > 50 or np.max(np.abs(w2)) > 50:
        return -1
    changed = int(np.sum(w1 != w2))
    if changed < 6 or changed > 15:
        return -1
    s = changed
    br = abs(float(w1[15]) - 1.0)
    if br < 0.15:
        s += 8
    if abs(float(w1[3])) < 0.1 and abs(float(w1[7])) < 0.1:
        s += 4
    return s

def scan(limit_mb=400):
    ent = manifest()
    idxs = sorted({i for (p, i) in ent if p == 1})
    hits = []
    processed = 0
    for idx in idxs:
        va, sz = ent.get((1, idx), (0, 0))
        x, y = load_pair(idx, va)
        if x is None:
            continue
        processed += x.nbytes // (1024 * 1024)
        if processed > limit_mb:
            break
        # stride 1 float, window 16 floats
        if len(x) < 16:
            continue
        w1 = np.lib.stride_tricks.sliding_window_view(x, 16)
        w2 = np.lib.stride_tricks.sliding_window_view(y, 16)
        # coarse vectorised filter
        finite = np.isfinite(w1).all(axis=1) & np.isfinite(w2).all(axis=1)
        small = (np.abs(w1) < 50).all(axis=1) & (np.abs(w2) < 50).all(axis=1)
        ch = (w1 != w2).sum(axis=1)
        br = np.abs(w1[:, 15] - 1.0) < 0.15
        mask = finite & small & (ch >= 6) & (ch <= 15) & br
        for off in np.nonzero(mask)[0][:8]:
            s = score_window(w1[off], w2[off])
            if s > 0:
                hits.append((s, idx, va + off * 4, ch[off]))
        if len(hits) > 4000:
            break
    return hits, processed

if __name__ == '__main__':
    hits, mb = scan()
    hits.sort(reverse=True)
    print(f'scanned {mb} MB, candidates={len(hits)}')
    for s, idx, va, ch in hits[:25]:
        print(f'  score={s:3d} idx={idx:4d} va=0x{va:012X} changed={ch}')
