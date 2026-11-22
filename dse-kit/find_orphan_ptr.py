"""find_orphan_ptr.py -- 从当前 ntoskrnl 内存镜像里找出指向"未知内核区域"的指针

指向已登记模块 → 正常
指向 ntoskrnl 自身 → 正常
指向以上两者之外的内核地址 → 就是隐藏驱动（KASLR 后的真实基址）
"""
import ctypes, struct
from ctypes import wintypes

nt = ctypes.WinDLL('ntdll')


class MOD(ctypes.Structure):
    _fields_ = [('Section', ctypes.c_void_p), ('MappedBase', ctypes.c_void_p),
                ('ImageBase', ctypes.c_void_p), ('ImageSize', wintypes.ULONG),
                ('Flags', wintypes.ULONG), ('LoadOrderIndex', wintypes.USHORT),
                ('InitOrderIndex', wintypes.USHORT), ('LoadCount', wintypes.USHORT),
                ('OffsetToFileName', wintypes.USHORT), ('FullPathName', ctypes.c_char * 256)]


size = 1 << 20
for _ in range(5):
    buf = ctypes.create_string_buffer(size)
    ret = wintypes.ULONG(0)
    if nt.NtQuerySystemInformation(11, buf, size, ctypes.byref(ret)) == 0:
        break
    size = ret.value + 0x1000
n = struct.unpack_from('<I', buf.raw, 0)[0]
mods = []
for i in range(n):
    m = MOD.from_buffer_copy(buf.raw, 8 + i * ctypes.sizeof(MOD))
    mods.append((m.ImageBase, m.ImageBase + m.ImageSize, m.FullPathName.decode('latin1')))
print(f"已登记模块 {len(mods)} 个")

def known(v):
    for a, b, _ in mods:
        if a <= v < b:
            return True
    return False

m = open(r'C:\ProgramData\ntoskrnl_mem.bin', 'rb').read()
hits = {}
for i in range(0, len(m) - 8):
    v = struct.unpack_from('<Q', m, i)[0]
    if v < 0xFFFF800000000000:
        continue
    if known(v):
        continue
    hits.setdefault(v, []).append(i)

print(f"指向未知内核区域的指针: {len(hits)} 个不同目标")
for v, rvas in sorted(hits.items())[:40]:
    print(f"  0x{v:016X}  被引用 {len(rvas)} 次  ntoskrnl rva={[hex(r) for r in rvas[:3]]}")
