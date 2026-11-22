"""dse.py -- 用已签名的 WinPmem 驱动 + MemProcFS 做内核读写，
           定位并修改 ci.dll 的代码完整性选项（g_CiOptions）。

用法:
  python dse.py mods                 # 列内核模块，找 ci.dll
  python dse.py scan                 # 扫 ci.dll 找 g_CiOptions 候选并读当前值
  python dse.py off                  # 置 0（关闭 DSE）
  python dse.py on                   # 置 6（恢复，让 Javelin 检查通过）
"""
import ctypes, os, struct, sys

VMM = r"E:\Users\MYX\Desktop\apex\.tools\forensics-python\memprocfs\vmm.dll"
VMM_DIR = os.path.dirname(VMM)
PID_KERNEL = 0xFFFFFFFF

LC_DIR = r"E:\Users\MYX\Desktop\apex\sources\leechcore-readonly\files"
for d in (VMM_DIR, LC_DIR):
    if os.path.isdir(d):
        os.add_dll_directory(d)
vmm = ctypes.CDLL(VMM)

vmm.VMMDLL_Initialize.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_char_p)]
vmm.VMMDLL_Initialize.restype = ctypes.c_void_p
vmm.VMMDLL_Close.argtypes = [ctypes.c_void_p]
vmm.VMMDLL_MemReadEx.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint64,
                                 ctypes.c_void_p, ctypes.c_uint32,
                                 ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32]
vmm.VMMDLL_MemReadEx.restype = ctypes.c_bool
vmm.VMMDLL_MemWrite.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint64,
                                ctypes.c_void_p, ctypes.c_uint32]
vmm.VMMDLL_MemWrite.restype = ctypes.c_bool
vmm.VMMDLL_Map_GetModuleU.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p,
                                      ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32]
vmm.VMMDLL_Map_GetModuleU.restype = ctypes.c_bool


def init():
    argv = ["", "-device", "pmem", "-disable-python", "-disable-symbols", "-norefresh", "-v"]
    arr = (ctypes.c_char_p * len(argv))(*[a.encode() for a in argv])
    h = vmm.VMMDLL_Initialize(len(argv), arr)
    if not h:
        print("[!] VMMDLL_Initialize failed (WinPmem loaded? device \\\\.\\pmem?)")
        sys.exit(1)
    return h


def get_module(h, name, pid=0):
    p = ctypes.c_void_p()
    if not vmm.VMMDLL_Map_GetModuleU(h, pid, name.encode(), ctypes.byref(p), 0):
        return None
    if not p.value:
        return None
    va = ctypes.cast(p, ctypes.POINTER(ctypes.c_uint64))[0]
    size = ctypes.cast(p, ctypes.POINTER(ctypes.c_uint64))[1]
    return va, size


def read_va(h, va, n, pid=PID_KERNEL):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_uint32(0)
    if not vmm.VMMDLL_MemReadEx(h, pid, va, buf, n, ctypes.byref(got), 0):
        return None
    return buf.raw[:got.value]


def write_va(h, va, data, pid=PID_KERNEL):
    buf = ctypes.create_string_buffer(data, len(data))
    return vmm.VMMDLL_MemWrite(h, pid, va, buf, len(data))


def rva_of(buf, rva):
    """粗粒度 RVA->文件偏移（只处理常见节布局：按节表换算）"""
    e_lfanew = struct.unpack_from('<I', buf, 0x3C)[0]
    nsec = struct.unpack_from('<H', buf, e_lfanew + 6)[0]
    optsz = struct.unpack_from('<H', buf, e_lfanew + 20)[0]
    sec = e_lfanew + 24 + optsz
    for i in range(nsec):
        s = sec + i * 40
        vsz, va, rsz, rp = struct.unpack_from('<IIII', buf, s + 8)
        if va <= rva < va + max(vsz, rsz):
            return rp + (rva - va)
    return None


def find_ci_options(h, ci_base, ci_size):
    """在 ci.dll 里找 `mov dword ptr [rip+disp32], 6`（C7 05 xx xx xx xx 06 00 00 00）"""
    img = read_va(h, ci_base, ci_size)
    if not img:
        print("[!] cannot read ci.dll image")
        return []
    cands = []
    for i in range(0, len(img) - 10):
        if img[i] == 0xC7 and img[i + 1] == 0x05:
            disp = struct.unpack_from('<i', img, i + 2)[0]
            imm = struct.unpack_from('<I', img, i + 6)[0]
            if imm not in (0, 1, 2, 6, 0xE):
                continue
            target_rva = i + 10 + disp
            if target_rva < 0 or target_rva >= ci_size:
                continue
            va = ci_base + target_rva
            cur = read_va(h, va, 4)
            if cur is None:
                continue
            cands.append((va, struct.unpack('<I', cur)[0], i))
    return cands


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    h = init()
    try:
        if cmd == 'mods':
            for name in ('ci.dll', 'ntoskrnl.exe', 'win32k.sys', 'eaanticheat.sys'):
                m = get_module(h, name)
                print(f"  {name:<18} " + (f"base=0x{m[0]:X} size=0x{m[1]:X}" if m else "NOT FOUND"))
            return
        m = get_module(h, 'ci.dll')
        if not m:
            print('[!] ci.dll not found')
            return
        base, size = m
        print(f"[*] ci.dll base=0x{base:X} size=0x{size:X}")
        cands = find_ci_options(h, base, size)
        print(f"[*] candidates ({len(cands)}):")
        for va, val, off in cands[:12]:
            print(f"    0x{va:X}  value=0x{val:X}  (module+0x{va-base:X})")
        if cmd == 'off' or cmd == 'on':
            if not cands:
                print('[!] no candidate'); return
            # 优先选当前值含 TESTSIGN(0x2) 或等于 6/0xE 的那个
            pick = cands[0]
            for va, val, off in cands:
                if val & 0x2 or val == 0xE:
                    pick = (va, val, off); break
            va, val, _ = pick
            new = 0 if cmd == 'off' else 6
            ok = write_va(h, va, struct.pack('<I', new))
            after = read_va(h, va, 4)
            print(f"[{'OK' if ok else 'FAIL'}] 0x{va:X}: 0x{val:X} -> " +
                  (f"0x{struct.unpack('<I', after)[0]:X}" if after else '?'))
    finally:
        vmm.VMMDLL_Close(h)


if __name__ == '__main__':
    main()
