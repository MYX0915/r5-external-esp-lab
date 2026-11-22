"""find_xrefs.py -- 在 ntoskrnl 内存镜像里搜索指向"隐藏驱动镜像"内部的指针

思路：内核的回调注册（线程通知/镜像通知/对象回调）最后都会在 ntoskrnl 的
      .data 里留下函数指针。若某个指针落在我们 dump 出来的隐藏镜像范围内，
      就说明那个镜像被内核当作回调函数调用了 —— 可以直接锁定它。

输出：每个命中 = 指针所在 RVA（ntoskrnl 内）+ 指向哪个隐藏镜像 + 镜像内偏移
"""
import glob, os, struct

HID = []
for f in glob.glob(r'C:\ProgramData\kmod_*.bin'):
    d = open(f, 'rb').read()
    if d[:2] != b'MZ':
        continue
    e = struct.unpack_from('<I', d, 0x3C)[0]
    if d[e:e+4] != b'PE\0\0':
        continue
    optsz = struct.unpack_from('<H', d, e + 20)[0]
    opt = e + 24
    size_img = struct.unpack_from('<I', d, opt + 56)[0]
    base = int(os.path.basename(f)[5:-4], 16)
    HID.append((base, size_img, os.path.basename(f)))

HID.sort()
print(f"隐藏镜像 {len(HID)} 个（按基址排序）")
for b, s, n in HID:
    print(f"  0x{b:016X} - 0x{b+s:016X}  size=0x{s:<7X} {n}")

m = open(r'C:\ProgramData\ntoskrnl_mem.bin', 'rb').read()

def which(v):
    for b, s, n in HID:
        if b <= v < b + s:
            return (n, v - b)
    return None

found = []
# 扫描整个镜像（8 字节对齐 + 非对齐都扫，指针不保证对齐）
step = 1
for i in range(0, len(m) - 8, step):
    v = struct.unpack_from('<Q', m, i)[0]
    if v < 0xFFFFF80000000000 or v > 0xFFFFFFFFFFFFFFFF:
        continue
    hit = which(v)
    if hit:
        found.append((i, v, hit[0], hit[1]))

print(f"\n命中 {len(found)} 处指针指向隐藏镜像")
agg = {}
for rva, v, img, off in found:
    agg.setdefault(img, []).append((rva, off, v))
for img, lst in agg.items():
    print(f"\n  {img}: {len(lst)} 处引用")
    for rva, off, v in lst[:12]:
        print(f"     ntoskrnl rva=0x{rva:X} -> 镜像内 +0x{off:X}  (0x{v:X})")
