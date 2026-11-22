"""dis_api.py -- 反汇编运行中的 NtAllocateVirtualMemory，检查调用目标是否跳出 ntoskrnl

用法: python dis_api.py NtAllocateVirtualMemory [maxbytes]
"""
import sys, struct, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kva
from capstone import *

k = kva.KVA()
base, size = kva.nt_base()


def exports():
    hdr = k.read(base, 0x1000)
    e = struct.unpack_from('<I', hdr, 0x3C)[0]
    nt = hdr[e:]
    exp_rva, _ = struct.unpack_from('<II', nt, 0x18 + 0x70)
    d = k.read(base + exp_rva, 0x400)
    nfuncs = struct.unpack_from('<I', d, 0x14)[0]
    nnames = struct.unpack_from('<I', d, 0x18)[0]
    af, an, ao = struct.unpack_from('<III', d, 0x1C)
    names = k.read(base + an, nnames * 4)
    funcs = k.read(base + af, nfuncs * 4)
    ords = k.read(base + ao, nnames * 2)
    out = {}
    inv = {}
    for i in range(nnames):
        nrva = struct.unpack_from('<I', names, i * 4)[0]
        nm = k.read(base + nrva, 64)
        if not nm:
            continue
        nm = nm.split(b'\0')[0].decode('latin1')
        oi = struct.unpack_from('<H', ords, i * 2)[0]
        frva = struct.unpack_from('<I', funcs, oi * 4)[0]
        out[nm] = frva
        inv.setdefault(frva, nm)
    return out, inv


def main():
    api = sys.argv[1] if len(sys.argv) > 1 else 'NtAllocateVirtualMemory'
    maxb = int(sys.argv[2]) if len(sys.argv) > 2 else 0x200
    exp, inv = exports()
    if api not in exp:
        print(f'{api} not exported'); return
    rva = exp[api]
    code = k.read(base + rva, maxb)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    print(f"=== {api} rva=0x{rva:X}  va=0x{base+rva:X} ===")
    n = 0
    for ins in md.disasm(code, base + rva):
        irva = ins.address - base
        note = ''
        if ins.mnemonic in ('call', 'jmp') and ins.op_str.startswith('0x'):
            tgt = int(ins.op_str, 16)
            inmod = base <= tgt < base + size
            if not inmod:
                note = '   <<< 目标在 ntoskrnl 之外 !!!'
            else:
                trva = tgt - base
                if trva in inv:
                    note = f'   -> {inv[trva]}'
        print(f"  +0x{irva:<7X} {ins.mnemonic:<7} {ins.op_str}{note}")
        n += 1
        if n > 70:
            break


if __name__ == '__main__':
    main()
