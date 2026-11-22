"""resolve_rip.py -- 用候选 KASLR 基址把崩溃 RIP 还原到 ntoskrnl 的导出函数
用法: python resolve_rip.py 0xFFFFF8039CEF63F5 [0x...]
"""
import struct, sys, importlib.util

KRNL = r"C:\Windows\System32\ntoskrnl.exe"

src = open(r"E:\Users\MYX\Desktop\test-game\tools\pe_exports.py").read()
ns = {}
exec(src.split("for path in sys.argv")[0], ns)
d, base, secs, rva2off, exp = ns['parse'](KRNL)

# 取 SizeOfImage
e = struct.unpack_from('<I', d, 0x3C)[0]
optsz = struct.unpack_from('<H', d, e + 20)[0]
opt = e + 24
image_size = struct.unpack_from('<I', d, opt + 56)[0]
print(f"ntoskrnl SizeOfImage = 0x{image_size:X}  exports={len(exp)}")

# 排序导出（RVA -> name），用于找"最接近且在下方"的导出
items = sorted(((v, k) for k, v in exp.items()))
rvas = [r for r, _ in items]


def enclosing(rva):
    import bisect
    i = bisect.bisect_right(rvas, rva) - 1
    if i < 0:
        return None, 0
    return items[i][1], rva - items[i][0]


for arg in sys.argv[1:]:
    rip = int(arg, 16)
    print(f"\n=== RIP 0x{rip:X} ===")
    hits = []
    for b in range(0xFFFFF80000000000, 0xFFFFF80800000000, 0x10000):
        rva = rip - b
        if 0 <= rva < image_size:
            name, off = enclosing(rva)
            if name and off < 0x8000:          # 函数内 32KB 内
                hits.append((b, rva, name, off))
    if not hits:
        print("  no plausible candidate")
    for b, rva, name, off in hits[:8]:
        print(f"  base=0x{b:X}  rva=0x{rva:X}  -> {name}+0x{off:X}")
