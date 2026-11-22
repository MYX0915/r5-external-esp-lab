"""wp_writetest.py -- 验证 WinPmem 驱动是否支持物理内存写（安全测试：写回原值）"""
import ctypes, os, sys

LC = r"E:\Users\MYX\Desktop\apex\sources\leechcore-readonly\files\leechcore.dll"
os.add_dll_directory(os.path.dirname(LC))
lc = ctypes.CDLL(LC)

lc.LcCreate.argtypes = [ctypes.c_char_p]
lc.LcCreate.restype = ctypes.c_void_p
lc.LcClose.argtypes = [ctypes.c_void_p]
lc.LcRead.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_void_p]
lc.LcRead.restype = ctypes.c_bool
lc.LcWrite.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_void_p]
lc.LcWrite.restype = ctypes.c_bool
lc.LcGetOption.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p]
lc.LcGetOption.restype = ctypes.c_bool
lc.LcSetOption.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p]
lc.LcSetOption.restype = ctypes.c_bool

h = lc.LcCreate(b"pmem")
if not h:
    print("[!] LcCreate(pmem) failed - WinPmem service not running?")
    sys.exit(1)
print("[+] LeechCore attached to pmem")

try:
    # 取总物理内存大小（LC_OPT_CORE_MEMORYMODEL 等选项不一定可用，直接试读）
    for pa in (0x1000, 0x100000, 0x2000000):
        buf = ctypes.create_string_buffer(16)
        ok = lc.LcRead(h, pa, 16, buf)
        print(f"read  phys 0x{pa:X}: ok={ok} data={buf.raw[:16].hex()}")

    pa = 0x100000
    buf = ctypes.create_string_buffer(16)
    if not lc.LcRead(h, pa, 16, buf):
        print("[!] baseline read failed"); sys.exit(2)
    original = buf.raw[:16]
    wbuf = ctypes.create_string_buffer(original, 16)
    okw = lc.LcWrite(h, pa, 16, wbuf)
    print(f"write phys 0x{pa:X} (same bytes): ok={okw}")

    buf2 = ctypes.create_string_buffer(16)
    lc.LcRead(h, pa, 16, buf2)
    print(f"readback: {buf2.raw[:16].hex()}  unchanged={buf2.raw[:16] == original}")
finally:
    lc.LcClose(h)
