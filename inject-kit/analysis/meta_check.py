#!/usr/bin/env python3
"""按 .meta 侧车文件筛选有效 dump 样本。

每个 dump 现在会生成 <name>.bin.meta，格式:
  #!/ mdump meta
  va=0x<地址> len=0x<请求长度>
  #chunk_off status got want
  0x<off> 0x<status> <got> <want>
  ...
  #summary wrote=0x<X> ok=<n> bad=<m> firstBadOff=0x<O> verdict=<COMPLETE|PARTIAL|FAILED>

用法:
  python meta_check.py <dir>          # 统计目录内所有样本
  python meta_check.py <dir> --valid  # 只列出 verdict=COMPLETE 的文件
"""
import glob, os, sys, collections

def parse_meta(path):
    info = {"verdict": None, "va": None, "len": None, "ok": 0, "bad": 0, "firstBadOff": None}
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#summary"):
                for tok in line.split():
                    if tok.startswith("wrote="):   info["wrote"] = tok.split("=")[1]
                    elif tok.startswith("ok="):    info["ok"] = int(tok.split("=")[1])
                    elif tok.startswith("bad="):   info["bad"] = int(tok.split("=")[1])
                    elif tok.startswith("firstBadOff="): info["firstBadOff"] = tok.split("=")[1]
                    elif tok.startswith("verdict="): info["verdict"] = tok.split("=")[1]
            elif line.startswith("va="):
                for tok in line.split():
                    if tok.startswith("va="):  info["va"] = tok.split("=")[1]
                    elif tok.startswith("len="): info["len"] = tok.split("=")[1]
    return info

def main():
    d = sys.argv[1] if len(sys.argv) > 1 else r"C:\ProgramData\scdump"
    only_valid = "--valid" in sys.argv
    metas = glob.glob(os.path.join(d, "*.meta"))
    if not metas:
        print("未找到 .meta 文件（驱动需为 2026-11-24 08:57:58 之后的版本）")
        return
    stat = collections.Counter()
    for m in metas:
        i = parse_meta(m)
        v = i["verdict"] or "NOSUMMARY"
        stat[v] += 1
        if only_valid and v == "COMPLETE":
            print(os.path.basename(m)[:-5])
    print("\n样本判定统计:")
    total = sum(stat.values())
    for k, c in sorted(stat.items()):
        if total:
            print("   %-12s %5d  (%.1f%%)" % (k, c, 100.0*c/total))
    print("   合计         %5d" % total)

if __name__ == "__main__":
    main()
