import ctypes, os
VMM = r"E:\Users\MYX\Desktop\apex\.tools\forensics-python\memprocfs\vmm.dll"
LC  = r"E:\Users\MYX\Desktop\apex\sources\leechcore-readonly\files"
for d in (os.path.dirname(VMM), LC):
    if os.path.isdir(d): os.add_dll_directory(d)
vmm = ctypes.CDLL(VMM)
vmm.VMMDLL_Initialize.argtypes=[ctypes.c_uint32, ctypes.POINTER(ctypes.c_char_p)]
vmm.VMMDLL_Initialize.restype=ctypes.c_void_p
vmm.VMMDLL_Map_GetModuleU.argtypes=[ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32]
vmm.VMMDLL_Map_GetModuleU.restype=ctypes.c_bool
vmm.VMMDLL_Close.argtypes=[ctypes.c_void_p]

for args in (["","-device","pmem","-disable-python","-disable-symbols","-v"],
             ["","-device","pmem","-disable-python","-v"]):
    a=(ctypes.c_char_p*len(args))(*[x.encode() for x in args])
    h=vmm.VMMDLL_Initialize(len(args),a)
    print("init:",bool(h),"args:",args[2:])
    if not h: continue
    for pid in (0, 4, 0xFFFFFFFF):
        p=ctypes.c_void_p()
        ok=vmm.VMMDLL_Map_GetModuleU(h,pid,b"ci.dll",ctypes.byref(p),0)
        print(f"  pid={pid} ok={ok} ptr={p.value}")
    vmm.VMMDLL_Close(h)
