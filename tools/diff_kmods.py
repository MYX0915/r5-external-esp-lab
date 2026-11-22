import re, ctypes, struct
from ctypes import wintypes

# 1) 从 dumper 日志里取扫描到的 PE 列表
log = open(r'C:\ProgramData\kmaplog.txt','r',errors='ignore').read()
pe = {}
for m in re.finditer(r'\[dumper\] PE base=0x([0-9A-F]+) size=0x([0-9A-F]+) ts=0x([0-9A-F]+)', log):
    pe[int(m.group(1),16)] = (int(m.group(2),16), int(m.group(3),16))
print(f"scan PEs: {len(pe)}")

# 2) 模块列表
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
    if nt.NtQuerySystemInformation(11,buf,size,ctypes.byref(ret))==0: break
    size=ret.value+0x1000
n=struct.unpack_from('<I',buf.raw,0)[0]
mods={}
for i in range(n):
    m=MOD.from_buffer_copy(buf.raw, 8+i*ctypes.sizeof(MOD))
    mods[m.ImageBase]=(m.ImageSize, m.FullPathName.decode('latin1'))
print(f"modules : {n}")

hidden = [(b,s,t) for b,(s,t) in pe.items() if b not in mods]
print(f"\n=== 内存里有、但不在模块列表里的镜像: {len(hidden)} ===")
for b,s,t in sorted(hidden):
    print(f"  base=0x{b:016X} size=0x{s:<8X} ts=0x{t:08X}")
