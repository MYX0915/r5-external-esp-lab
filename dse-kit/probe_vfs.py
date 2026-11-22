import ctypes, os
VMM = r"E:\Users\MYX\Desktop\apex\.tools\forensics-python\memprocfs\vmm.dll"
LC  = r"E:\Users\MYX\Desktop\apex\sources\leechcore-readonly\files"
for d in (os.path.dirname(VMM), LC):
    if os.path.isdir(d): os.add_dll_directory(d)
vmm = ctypes.CDLL(VMM)
vmm.VMMDLL_Initialize.argtypes=[ctypes.c_uint32, ctypes.POINTER(ctypes.c_char_p)]
vmm.VMMDLL_Initialize.restype=ctypes.c_void_p
vmm.VMMDLL_Close.argtypes=[ctypes.c_void_p]

class ENTRY(ctypes.Structure):
    _fields_=[("szName",ctypes.c_char*256),("fDirectory",ctypes.c_bool),
              ("_pad",ctypes.c_ubyte*7),("cb",ctypes.c_uint64),
              ("ft",ctypes.c_uint64),("_res",ctypes.c_uint64*4)]

vmm.VMMDLL_VfsListU.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.POINTER(ctypes.c_void_p)]
vmm.VMMDLL_VfsListU.restype=ctypes.c_bool

args=["","-device","pmem","-disable-python","-disable-symbols","-v"]
a=(ctypes.c_char_p*len(args))(*[x.encode() for x in args])
h=vmm.VMMDLL_Initialize(len(args),a)
print("init",bool(h))

def listdir(path):
    p=ctypes.c_void_p()
    if not vmm.VMMDLL_VfsListU(h,path.encode(),ctypes.byref(p)):
        print(f"{path}: list failed"); return
    # VMMDLL_VFS_LIST: h(8) pEntries(8) cEntries(4)+pad ...
    n=ctypes.cast(p,ctypes.POINTER(ctypes.c_uint32))[2]
    arr=ctypes.cast(p,ctypes.POINTER(ctypes.c_void_p))[1]
    print(f"{path}: {n} entries")
    for i in range(min(n,25)):
        e=ctypes.cast(arr + i*ctypes.sizeof(ENTRY), ctypes.POINTER(ENTRY)).contents
        print("   ", e.szName.decode('latin1'), "DIR" if e.fDirectory else f"size={e.cb}")

listdir("/")
listdir("/sys")
listdir("/sys/modules")
vmm.VMMDLL_Close(h)
