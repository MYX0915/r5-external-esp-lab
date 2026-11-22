import ctypes, struct, os
from ctypes import wintypes
nt = ctypes.WinDLL('ntdll')
class MOD(ctypes.Structure):
    _fields_=[('Section',ctypes.c_void_p),('MappedBase',ctypes.c_void_p),('ImageBase',ctypes.c_void_p),
              ('ImageSize',wintypes.ULONG),('Flags',wintypes.ULONG),
              ('LoadOrderIndex',wintypes.USHORT),('InitOrderIndex',wintypes.USHORT),
              ('LoadCount',wintypes.USHORT),('OffsetToFileName',wintypes.USHORT),
              ('FullPathName',ctypes.c_char*256)]
size=1<<20
for _ in range(5):
    buf=ctypes.create_string_buffer(size); ret=wintypes.ULONG(0)
    if nt.NtQuerySystemInformation(11, buf, size, ctypes.byref(ret))==0: break
    size=ret.value+0x1000
n=struct.unpack_from('<I', buf.raw, 0)[0]
stride=ctypes.sizeof(MOD)
rows=[]
for i in range(n):
    m=MOD.from_buffer_copy(buf.raw, 8+i*stride)
    path=m.FullPathName.decode('latin1')
    rows.append((m.ImageBase, m.ImageSize, path))
# 打印:文件名不在标准 drivers 目录 / 路径非常规的模块
print("=== 非标准路径 / 可疑模块 ===")
for base,size_,path in rows:
    p=path.lower()
    if '\\systemroot\\system32\\drivers\\' not in p and '\\systemroot\\system32\\' not in p:
        print(f"  0x{base:016X} size=0x{size_:<7X} {path}")
print("\n=== 名字里带数字随机感 / 全部模块名（最后 40 个）===")
for base,size_,path in rows[-40:]:
    print(f"  0x{base:016X} 0x{size_:<7X} {path}")

