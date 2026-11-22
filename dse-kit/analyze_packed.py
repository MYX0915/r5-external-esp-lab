"""analyze_packed.py -- 分析 ts=0 那批加壳镜像：入口反汇编 + 外部引用（RIP 相对目标落在镜像外）

用途：判断这些镜像调用了哪些外部代码（可能是 ntoskrnl 导出或其它模块），
      从而推断它们是什么、以及是否在做 hook/回调注册。
"""
import glob, os, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

md = Cs(CS_ARCH_X86, CS_MODE_64)

def parse(d):
    e = struct.unpack_from('<I', d, 0x3C)[0]
    coff = e + 4
    nsec = struct.unpack_from('<H', d, coff + 2)[0]
    optsz = struct.unpack_from('<H', d, coff + 16)[0]
    opt = coff + 20
    pe64 = struct.unpack_from('<H', d, opt)[0] == 0x20b
    ep = struct.unpack_from('<I', d, opt + 16)[0]
    size_img = struct.unpack_from('<I', d, opt + 56)[0]
    secs = []
    so = opt + optsz
    for i in range(nsec):
        s = so + i * 40
        nm = d[s:s+8].rstrip(b'\0').decode('latin1', 'ignore')
        vs, va, rs, rp = struct.unpack_from('<IIII', d, s + 8)
        ch = struct.unpack_from('<I', d, s + 36)[0]
        secs.append((nm, va, vs, rp, rs, ch))
    return ep, size_img, secs, pe64

def rva2off(secs, rva):
    for nm, va, vs, rp, rs, ch in secs:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None

for f in sorted(glob.glob(r'C:\ProgramData\kmod_*.bin')):
    d = open(f, 'rb').read()
    try:
        ep, size_img, secs, pe64 = parse(d)
    except Exception:
        continue
    ts = struct.unpack_from('<I', d, struct.unpack_from('<I', d, 0x3C)[0] + 8)[0]
    if ts != 0:
        continue
    name = os.path.basename(f)
    print(f"\n=== {name}  img=0x{size_img:X} ep=0x{ep:X} ===")
    for nm, va, vs, rp, rs, ch in secs:
        flags = ''.join([c for c, m in (('R', 0x40000000), ('W', 0x80000000), ('X', 0x20000000)) if ch & m])
        print(f"    {nm or '(noname)':<10} va=0x{va:<7X} vs=0x{vs:<7X} flags={flags}")
    off = rva2off(secs, ep)
    if off is None:
        continue
    code = d[off:off + 64]
    print("    entry:")
    for ins in md.disasm(code, ep):
        print(f"      +0x{ins.address:X} {ins.mnemonic:<7} {ins.op_str}")
        if ins.address > ep + 24:
            break
    # 找 rip 相对引用，目标在镜像外
    ext = []
    for nm, va, vs, rp, rs, ch in secs:
        if not (ch & 0x20000000):
            continue
        body = d[rp:rp + rs]
        for ins in md.disasm(body, va):
            if 'rip' not in ins.op_str:
                continue
            import re
            m = re.search(r'rip \+ (0x[0-9a-f]+)', ins.op_str)
            sign = 1
            if not m:
                m = re.search(r'rip - (0x[0-9a-f]+)', ins.op_str)
                sign = -1
            if not m:
                continue
            disp = int(m.group(1), 16) * sign
            t = ins.address + ins.size + disp
            if t < 0 or t >= size_img:
                ext.append((ins.address, t, ins.mnemonic))
    if ext:
        uniq = sorted({t for _, t, _ in ext})[:8]
        print(f"    外部引用 {len(ext)} 处，去重前 8 个目标: " + ', '.join(f'0x{t:X}' for t in uniq))
    else:
        print("    外部引用: 无")
