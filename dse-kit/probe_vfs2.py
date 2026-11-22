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
    _fields_=[("szName",ctypes.c_char*256),("fDirectory",ctypes.c_uint8),
              ("_p1",ctypes.c_uint8*7),("cb",ctypes.c_uint64),
              ("ft",ctypes.c_uint64),("_p2",ctypes.c_uint8*32)]
class LIST(ctypes.Structure):
    _fields_=[("pEntries",ctypes.POINTER(ENTRY)),("cEntries",ctypes.c_uint32),("_p",ctypes.c_uint32)]

vmm.VMMDLL_VfsListU.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.POINTER(ctypes.POINTER(LIST))]
vmm.VMMDLL_VfsListU.restype=ctypes.c_bool

args=["","-device","pmem","-disable-python","-disable-symbols","-v"]
a=(ctypes.c_char_p*len(args))(*[x.encode() for x in args])
h=vmm.VMMDLL_Initialize(len(args),a)
print("init",bool(h))
for path in ("/","/sys","/sys/modules"):
    lp=ctypes.POINTER(LIST)()
    ok=vmm.VMMDLL_VfsListU(h,path.encode(),ctypes.byref(lp))
    print(f"{path}: ok={ok}", end="")
    if ok and lp:
        print(f" entries={lp.contents.cEntries}")
        for i in range(min(lp.contents.cEntries,15)):
            e=lp.contents.pEntries[i]
            print("   ",e.szName.decode('latin1'),"DIR" if e.fDirectory else f"size={e.cb}")
    else: print()
vmm.VMMDLL_Close(h)
