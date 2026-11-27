"""直接扫描 VPK 数据包里的明文 Squirrel 脚本

Apex 的 .nut/.gnut 脚本在 VPK 里通常是明文（不压缩）。
按 ASCII 可读性切分，找出包含 Squirrel 关键字的块。
"""
import io
import os
import re
import sys

BASE = r"E:\Users\MYX\Desktop\test-game\refs\squirrel\vpk\CheatsFolder"
DATA = os.path.join(BASE, "client_frontend.bsp.pak000_000.vpk")
OUTDIR = r"E:\Users\MYX\Desktop\test-game\refs\squirrel\extracted"

KEYS = [b"global function", b"void function", b"thread ", b"uiGlobal",
        b"GetRootPanel", b"HudElement", b"RuiCreate", b"AddThread",
        b"void ", b"string ", b"entity "]


def readable_runs(buf, min_len=2000):
    """返回 [(start, end)] 的可读 ASCII 连续块"""
    runs = []
    start = None
    n = len(buf)
    i = 0
    while i < n:
        c = buf[i]
        if 9 <= c <= 13 or 32 <= c <= 126:
            if start is None:
                start = i
            i += 1
        else:
            if start is not None and i - start >= min_len:
                runs.append((start, i))
            start = None
            i += 1
    if start is not None and n - start >= min_len:
        runs.append((start, n))
    return runs


def main():
    size = os.path.getsize(DATA)
    print("数据包: %s  %.1f MB" % (os.path.basename(DATA), size / 1024 / 1024))
    buf = io.open(DATA, "rb").read()
    runs = readable_runs(buf)
    print("可读块（>=2KB）: %d 个" % len(runs))

    os.makedirs(OUTDIR, exist_ok=True)
    hits = []
    for (s, e) in runs:
        chunk = buf[s:e]
        score = sum(1 for k in KEYS if k in chunk)
        if score >= 3:
            hits.append((score, s, e, chunk))

    hits.sort(key=lambda x: -x[0])
    print("含 ≥3 个 Squirrel 关键字的块: %d 个\n" % len(hits))

    for idx, (score, s, e, chunk) in enumerate(hits[:40]):
        text = chunk.decode("latin1")
        first = text.split("\n", 1)[0][:80]
        print("[%2d] score=%d off=0x%08X size=%d  %s" % (idx, score, s, e - s, first.strip()))

    # 导出前 20 个
    for idx, (score, s, e, chunk) in enumerate(hits[:20]):
        p = os.path.join(OUTDIR, "chunk_%02d_%08X.txt" % (idx, s))
        io.open(p, "wb").write(chunk)
    print("\n已导出前 20 个到:", OUTDIR)

    # 顺便统计整个包里出现的 .nut / .gnut 名称
    names = set(re.findall(rb"[\w/]{3,60}\.(?:nut|gnut)", buf))
    print("\n=== 包内出现的脚本文件名（前 40）===")
    for nm in sorted(names)[:40]:
        print("  " + nm.decode("latin1"))


if __name__ == "__main__":
    main()
