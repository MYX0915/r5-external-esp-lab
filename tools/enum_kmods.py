import ctypes, struct
from ctypes import wintypes
nt = ctypes.WinDLL('ntdll')
class UNICODE_STRING(ctypes.Structure):
    _fields_=[('Length',wintypes.USHORT),('MaximumLength',wintypes.USHORT),('Buffer',wintypes.LPWSTR)]
class RTL_PROCESS_MODULE(ctypes.Structure):
    _fields_=[('Section',wintypes.HANDLE),('MappedBase',ctypes.c_void_p),('ImageBase',ctypes.c_void_p),
              ('ImageSize',wintypes.ULONG),('Flags',wintypes.ULONG),('LoadOrderIndex',wintypes.USHORT),
              ('InitOrderIndex',wintypes.USHORT),('LoadCount',wintypes.USHORT),('OffsetToFileName',wintypes.USHORT),
              ('FullPathName',ctypes.c_char*256)]
size=1<<20
for _ in range(4):
    buf=ctypes.create_string_buffer(size); ret=wintypes.ULONG(0)
    st=nt.NtQuerySystemInformation(11, buf, size, ctypes.byref(ret))
    if st==0: break
    size=ret.value+0x1000
n=struct.unpack_from('<I', buf.raw, 0)[0]
print('modules:', n)
off=4
for i in range(n):
    m=RTL_PROCESS_MODULE.from_buffer_copy(buf.raw, off)
    off += 4 + 256 + 2*8 + 4*2 + 2*4   # 粗略
    name=m.FullPathName.decode('latin1')
    if any(k in name.lower() for k in ('eaac','anticheat','javelin','ea_')):
        print(f"  0x{m.ImageBase:016X}  size=0x{m.ImageSize:<8X} {name}")
