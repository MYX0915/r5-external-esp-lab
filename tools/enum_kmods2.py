import ctypes, struct
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
    st=nt.NtQuerySystemInformation(11, buf, size, ctypes.byref(ret))
    if st==0: break
    size=ret.value+0x1000
n=struct.unpack_from('<I', buf.raw, 0)[0]
stride=ctypes.sizeof(MOD)
print(f'modules={n} stride={stride}')
hits=0
for i in range(n):
    m=MOD.from_buffer_copy(buf.raw, 4+i*stride)
    name=m.FullPathName.decode('latin1')
    low=name.lower()
    if any(k in low for k in ('eaac','anticheat','javelin','ea_')):
        print(f"  0x{m.ImageBase:016X} size=0x{m.ImageSize:<7X} {name}")
        hits+=1
print('hits=',hits)
