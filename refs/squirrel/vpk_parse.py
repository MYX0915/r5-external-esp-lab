"""解析 Apex/Respawn VPK 目录树，列出并提取文件

格式（VPK v1 风格，Respawn 变体）：
  header: magic(4)=0x55AA1234, version(4), treeSize(4), fileDataSize(4)
  tree  : 层级 null-terminated 字符串
            extension \\0
              path \\0
                filename \\0
                  条目 18 字节: crc(4) preload(2) archiveIdx(2) offset(4) length(4) terminator(2)
                空字符串 \\0 = 该层结束
"""
import io
import os
import struct
import sys

BASE = r"E:\Users\MYX\Desktop\test-game\refs\squirrel\vpk\CheatsFolder"
DIR_VPK = os.path.join(BASE, "englishclient_frontend.bsp.pak000_dir.vpk")
DATA_VPK = os.path.join(BASE, "client_frontend.bsp.pak000_000.vpk")


def read_cstr(buf, pos):
    end = buf.find(b"\x00", pos)
    if end < 0:
        return None, pos
    return buf[pos:end].decode("latin1"), end + 1


def parse_tree(dir_vpk):
    raw = io.open(dir_vpk, "rb").read()
    magic, version, tree_size, file_data_size = struct.unpack_from("<IIII", raw, 0)
    print("magic=0x%08X version=0x%08X treeSize=%d dataSize=%d 文件总长=%d"
          % (magic, version, tree_size, file_data_size, len(raw)))
    pos = 16
    entries = []
    while pos < len(raw):
        ext, pos = read_cstr(raw, pos)
        if ext is None or ext == "":
            if ext == "":
                continue
            break
        while True:
            path, pos = read_cstr(raw, pos)
            if path is None:
                break
            if path == "":
                break
            while True:
                name, pos = read_cstr(raw, pos)
                if name is None:
                    break
                if name == "":
                    break
                if pos + 18 > len(raw):
                    break
                crc, preload, arch, off, ln, term = struct.unpack_from("<IHHIIH", raw, pos)
                pos += 18
                full = "%s/%s.%s" % (path, name, ext) if path else "%s.%s" % (name, ext)
                entries.append({
                    "path": full, "crc": crc, "preload": preload,
                    "archive": arch, "offset": off, "length": ln,
                })
            if pos >= len(raw):
                break
        if pos >= len(raw):
            break
    return entries


def main():
    ents = parse_tree(DIR_VPK)
    print("文件数: %d" % len(ents))
    print()
    # 按目录统计
    dirs = {}
    for e in ents:
        d = e["path"].rsplit("/", 1)[0] if "/" in e["path"] else "(root)"
        dirs[d] = dirs.get(d, 0) + 1
    print("=== 目录分布（前 25）===")
    for d, n in sorted(dirs.items(), key=lambda x: -x[1])[:25]:
        print("  %-60s %4d" % (d, n))

    print()
    print("=== 脚本类文件（nut/gnut/script）===")
    scripts = [e for e in ents if e["path"].lower().endswith((".nut", ".gnut", ".txt", ".json"))]
    print("  共 %d 个" % len(scripts))
    for e in scripts[:60]:
        print("  %-70s off=0x%08X len=%d" % (e["path"], e["offset"], e["length"]))

    out = os.path.join(os.path.dirname(BASE), "vpk_listing.txt")
    with io.open(out, "w", encoding="utf-8") as f:
        for e in ents:
            f.write("%-80s off=0x%08X len=%d\n" % (e["path"], e["offset"], e["length"]))
    print("\n完整清单已写入:", out)


if __name__ == "__main__":
    main()
