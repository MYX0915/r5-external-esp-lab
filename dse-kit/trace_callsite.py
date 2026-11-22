"""trace_callsite.py -- 追踪 ntoskrnl rva 0xBD72A2 处的调用，以及被调隐藏镜像函数

输出：
  1. 该 rva 所属函数（用 .pdata 定界）：起止 rva、大小
  2. 该函数是否为导出函数（有名字）
  3. 0xBD72A2 前后 0x60 字节的反汇编
  4. 从 call 指令解出真实目标（相对/间接）
  5. 隐藏镜像 +0xF8B8 处的反汇编
"""
import glob, os, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

NT_BASE = 0xFFFFF800E2C00000
CALLSITE = 0xBD72A2
IMG_HINT = 0xF8B8

m = open(r'C:\ProgramData\ntoskrnl_mem.bin', 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

# --- .pdata 函数边界
PD_RVA, PD_SIZE = 0xE2000, 0x6F8F4
funcs = []
for i in range(PD_SIZE // 12):
    b, e2, u = struct.unpack_from('<III', m, PD_RVA + i * 12)
    if b == 0 or b >= len(m):
        continue
    funcs.append((b, e2))
funcs.sort()

def containing(rva):
    best = None
    for b, e2 in funcs:
        if b <= rva < e2:
            best = (b, e2)
        if b > rva:
            break
    return best

# --- 导出表
hdr_e = struct.unpack_from('<I', m, 0x3C)[0]
opt = hdr_e + 24
exp_rva, _ = struct.unpack_from('<II', m, opt + 0x70)
nn = struct.unpack_from('<I', m, exp_rva + 0x18)[0]
af, an, ao = struct.unpack_from('<III', m, exp_rva + 0x1C)
exp = {}
for i in range(nn):
    nr = struct.unpack_from('<I', m, an + i * 4)[0]
    nm = m[nr:m.find(b'\0', nr)].decode('latin1', 'ignore')
    oi = struct.unpack_from('<H', m, ao + i * 2)[0]
    fr = struct.unpack_from('<I', m, af + oi * 4)[0]
    exp[fr] = nm

f = containing(CALLSITE)
print(f"调用点 rva=0x{CALLSITE:X}")
if f:
    print(f"所属函数: 0x{f[0]:X} ~ 0x{f[1]:X}  (大小 0x{f[1]-f[0]:X})")
    print(f"函数名  : {exp.get(f[0], '(未导出)')}")
    # 附近有没有导出函数（可能是内部子函数）
    near = [(r, n) for r, n in exp.items() if f[0] - 0x2000 <= r <= f[1]]
    if near:
        print("附近导出:", ', '.join(f'0x{r:X} {n}' for r, n in sorted(near)[:5]))
else:
    print("未在 .pdata 中找到所属函数")

print(f"\n--- 调用点前后反汇编 (rva 0x{CALLSITE-0x40:X} 起) ---")
start = CALLSITE - 0x40
for ins in md.disasm(m[start:start + 0xB0], start):
    mark = '  <<<<<' if ins.address == CALLSITE else ''
    tgt = ''
    if ins.mnemonic == 'call' and ins.op_str.startswith('0x'):
        t = int(ins.op_str, 16)
        tgt = f'   ; -> nt_rva 0x{t & 0xFFFFFFFF:X}'
    print(f"  +0x{ins.address:X} {ins.mnemonic:<7} {ins.op_str}{tgt}{mark}")

# --- 隐藏镜像
d = None
for fp in glob.glob(r'C:\ProgramData\kmod_*.bin'):
    if 'E3DF2000' in fp:
        d = open(fp, 'rb').read()
        print(f"\n=== 隐藏镜像 {os.path.basename(fp)} ({len(d)} bytes) ===")
        break
if d:
    e = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, e + 6)[0]
    optsz = struct.unpack_from('<H', d, e + 20)[0]
    opt2 = e + 24
    ep = struct.unpack_from('<I', d, opt2 + 16)[0]
    secs = []
    so = opt2 + optsz
    for i in range(nsec):
        s = so + i * 40
        nm = d[s:s + 8].rstrip(b'\0').decode('latin1', 'ignore')
        vs, va, rs, rp = struct.unpack_from('<IIII', d, s + 8)
        secs.append((nm, va, vs, rp, rs))
    print(f"入口点 = 0x{ep:X}")
    for nm, va, vs, rp, rs in secs:
        print(f"    {nm:<10} va=0x{va:<7X} vs=0x{vs:<7X}")

    def r2o(rva):
        for nm, va, vs, rp, rs in secs:
            if va <= rva < va + max(vs, rs):
                return rp + (rva - va)
        return None

    o = r2o(IMG_HINT)
    if o:
        print(f"\n--- 镜像 +0x{IMG_HINT:X} 反汇编 ---")
        for ins in md.disasm(d[o:o + 0x60], IMG_HINT):
            print(f"  +0x{ins.address:X} {ins.mnemonic:<7} {ins.op_str}")
