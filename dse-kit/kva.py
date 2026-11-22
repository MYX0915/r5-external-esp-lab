"""kva.py -- 基于 WinPmem 物理读 + 自己走页表，实现内核 VA 读取

用法:
  python kva.py ntbase                # 从 NtQuerySystemInformation 拿 ntoskrnl 基址
  python kva.py read <hexva> <len>    # 读内核 VA
  python kva.py mmcopy               # 检查 MmCopyMemory 是否被 hook
"""
import ctypes, struct, sys, os
from ctypes import wintypes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pmem_rw as P


class KVA:
    def __init__(self):
        self.d = P.DEVICE()
        self.cr3 = self.d.info['cr3'] & ~0xFFF
        self.pages = {}

    def _read_phys(self, pa, n):
        return self.d.read(pa, n)

    def _table(self, pa):
        if pa not in self.pages:
            self.pages[pa] = self._read_phys(pa, 0x1000)
        return self.pages[pa]

    def translate(self, va):
        pml4 = self._table(self.cr3)
        if not pml4:
            return None
        i4 = (va >> 39) & 0x1FF
        e4 = struct.unpack_from('<Q', pml4, i4 * 8)[0]
        if not (e4 & 1):
            return None
        pdpt = self._table(e4 & 0x000FFFFFFFFFF000)
        if not pdpt:
            return None
        i3 = (va >> 30) & 0x1FF
        e3 = struct.unpack_from('<Q', pdpt, i3 * 8)[0]
        if not (e3 & 1):
            return None
        if e3 & 0x80:                                  # 1GB page
            return (e3 & 0x000FFFFFC0000000) + (va & 0x3FFFFFFF)
        pd = self._table(e3 & 0x000FFFFFFFFFF000)
        if not pd:
            return None
        i2 = (va >> 21) & 0x1FF
        e2 = struct.unpack_from('<Q', pd, i2 * 8)[0]
        if not (e2 & 1):
            return None
        if e2 & 0x80:                                  # 2MB page
            return (e2 & 0x000FFFFFFFE00000) + (va & 0x1FFFFF)
        pt = self._table(e2 & 0x000FFFFFFFFFF000)
        if not pt:
            return None
        i1 = (va >> 12) & 0x1FF
        e1 = struct.unpack_from('<Q', pt, i1 * 8)[0]
        if not (e1 & 1):
            return None
        return (e1 & 0x000FFFFFFFFFF000) + (va & 0xFFF)

    def read(self, va, n):
        out = b''
        while n > 0:
            pa = self.translate(va)
            if pa is None:
                return None
            chunk = min(n, 0x1000 - (va & 0xFFF))
            data = self._read_phys(pa, chunk)
            if not data:
                return None
            out += data
            va += chunk
            n -= chunk
        return out


def nt_base():
    nt = ctypes.WinDLL('ntdll')
    class MOD(ctypes.Structure):
        _fields_ = [('Section', ctypes.c_void_p), ('MappedBase', ctypes.c_void_p),
                    ('ImageBase', ctypes.c_void_p), ('ImageSize', wintypes.ULONG),
                    ('Flags', wintypes.ULONG), ('LoadOrderIndex', wintypes.USHORT),
                    ('InitOrderIndex', wintypes.USHORT), ('LoadCount', wintypes.USHORT),
                    ('OffsetToFileName', wintypes.USHORT), ('FullPathName', ctypes.c_char * 256)]
    size = 1 << 20
    for _ in range(5):
        buf = ctypes.create_string_buffer(size); ret = wintypes.ULONG(0)
        if nt.NtQuerySystemInformation(11, buf, size, ctypes.byref(ret)) == 0:
            break
        size = ret.value + 0x1000
    n = struct.unpack_from('<I', buf.raw, 0)[0]
    stride = ctypes.sizeof(MOD)
    for i in range(n):
        m = MOD.from_buffer_copy(buf.raw, 8 + i * stride)
        if m.FullPathName.decode('latin1').lower().endswith('ntoskrnl.exe'):
            return m.ImageBase, m.ImageSize
    return None, None


MMCOPY_RVA = 0x249380

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'ntbase'
    if cmd == 'ntbase':
        b, s = nt_base()
        print(f'ntoskrnl base=0x{b:X} size=0x{s:X}')
    elif cmd == 'read':
        k = KVA()
        va = int(sys.argv[2], 16); n = int(sys.argv[3])
        d = k.read(va, n)
        print(d.hex(' ') if d else 'FAILED')
    elif cmd == 'mmcopy':
        b, s = nt_base()
        k = KVA()
        va = b + MMCOPY_RVA
        d = k.read(va, 16)
        if not d:
            print('read failed'); sys.exit(1)
        print(f'ntoskrnl+0x{MMCOPY_RVA:X} = {d.hex(" ")}')
        if d[0] == 0x48 and d[1] == 0xB8 and d[10] == 0xFF and d[11] == 0xE0:
            handler = struct.unpack_from('<Q', d, 2)[0]
            print(f'*** HOOKED *** handler = 0x{handler:X}')
        elif d[:12] == bytes.fromhex('48895C242055565741544155'[:24]):
            print('prologue 正常（未被 hook）')
        else:
            print('未知序言')
