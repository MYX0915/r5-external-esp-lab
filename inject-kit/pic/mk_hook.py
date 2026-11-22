"""mk_hook.py -- compute a hook site for mod!export

Prints hookrva / hookn / hookorig for sc3.sys (job file), and refuses sites whose
first N bytes contain RIP-relative memory operands or relative branches: those
cannot be copied verbatim into a trampoline.

usage: python mk_hook.py kernel32.dll SleepEx [minbytes]
"""
import ctypes, struct, sys
import capstone

def sysdir():
    buf = ctypes.create_unicode_buffer(260)
    ctypes.windll.kernel32.GetSystemDirectoryW(buf, 260)
    return buf.value

def read_file(mod):
    path = mod if '\\' in mod else sysdir() + '\\' + mod
    return path, open(path, 'rb').read()

def rva2off(d, rva):
    e_lfanew = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, e_lfanew + 6)[0]
    opt = e_lfanew + 24
    secoff = opt + struct.unpack_from('<H', d, e_lfanew + 20)[0]
    for i in range(nsec):
        b = secoff + i * 40
        vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', d, b + 8)
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rawptr + (rva - vaddr)
    return None

def export_rva(d, name):
    e_lfanew = struct.unpack_from('<I', d, 0x3C)[0]
    opt = e_lfanew + 24
    exp_rva, exp_size = struct.unpack_from('<II', d, opt + 112)
    if not exp_rva:
        return None, None
    off = rva2off(d, exp_rva)
    nnames = struct.unpack_from('<I', d, off + 24)[0]
    afunc = struct.unpack_from('<I', d, off + 28)[0]
    anames = struct.unpack_from('<I', d, off + 32)[0]
    aords = struct.unpack_from('<I', d, off + 36)[0]
    for i in range(nnames):
        n_off = rva2off(d, struct.unpack_from('<I', d, rva2off(d, anames) + i * 4)[0])
        nm = d[n_off:d.index(b'\0', n_off)].decode('ascii', 'replace')
        if nm == name:
            ordv = struct.unpack_from('<H', d, rva2off(d, aords) + i * 2)[0]
            frva = struct.unpack_from('<I', d, rva2off(d, afunc) + ordv * 4)[0]
            return frva, (exp_rva, exp_size)
    return None, (exp_rva, exp_size)

def main():
    mod = sys.argv[1]
    name = sys.argv[2]
    need = int(sys.argv[3]) if len(sys.argv) > 3 else 12
    path, d = read_file(mod)
    rva, exprange = export_rva(d, name)
    if rva is None:
        print('export not found'); return 2
    if exprange[0] and exprange[0] <= rva < exprange[0] + exprange[1]:
        print('forwarded export, resolve in kernelbase instead'); return 3
    off = rva2off(d, rva)
    code = d[off:off + 64]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    total = 0
    bad = []
    for ins in md.disasm(code, rva):
        total += ins.size
        rip = any(op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP
                  for op in ins.operands)
        rel = ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL)
        if rip or rel:
            bad.append(f'{ins.address:X}: {ins.mnemonic} {ins.op_str}')
        if total >= need:
            break
    if total < need:
        print('not enough bytes'); return 4
    if bad:
        print('REJECT: window contains position dependent instructions:')
        for b in bad:
            print('   ', b)
        return 5
    orig = code[:total]
    print(f'mod={path.split(chr(92))[-1]} export={name}')
    print(f'hookrva=0x{rva:X}')
    print(f'hookn={total}')
    print('hookorig=' + ' '.join(f'{b:02X}' for b in orig))
    print('---')
    for ins in md.disasm(orig, rva):
        print(f'   {ins.address:X}: {ins.mnemonic} {ins.op_str}')
    return 0

if __name__ == '__main__':
    sys.exit(main())
