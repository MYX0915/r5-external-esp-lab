"""find_cioptions.py -- 从 ci.dll 里静态定位 g_CiOptions 候选

思路：CiValidateFileObject / CiCheckSignedFile 这类函数入口会读一个 DWORD 全局，
      并 test 其低位（DSE 开关）。把这些 RIP 相对引用的目标收集起来就是候选。
"""
import importlib.util
from capstone import *

src = open(r"E:\Users\MYX\Desktop\test-game\tools\pe_exports.py").read()
ns = {}
exec(src.split("for path in sys.argv")[0], ns)
d, base, secs, rva2off, exp = ns['parse'](r"C:\Windows\System32\ci.dll")

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

TARGETS = ['CiValidateFileObject', 'CiCheckSignedFile', 'CiVerifyHashInCatalog',
           'CiInitialize', 'CiGetPEInformation']


def disasm(rva, length=0x300):
    off = rva2off(rva)
    code = d[off:off + length]
    return list(md.disasm(code, 0x140000000 + rva))


def rip_target(ins, insn_rva):
    """返回该指令里 RIP 相对操作数的目标 RVA（没有则 None）"""
    for op in ins.operands:
        if op.type == 3 and op.mem.base == 41:      # X86_OP_MEM, base = RIP(41)
            insn_len = ins.size
            return insn_rva + insn_len + op.mem.disp
    return None


cands = {}
for name in TARGETS:
    if name not in exp:
        continue
    rva = exp[name]
    print(f"\n=== {name}  RVA=0x{rva:X} ===")
    inss = disasm(rva, 0x200)
    shown = 0
    for ins in inss:
        irva = ins.address - 0x140000000
        t = rip_target(ins, irva)
        if t is None:
            continue
        # 只关心落在 ci.dll 镜像内的目标，且是 4 字节操作
        if not (0 <= t < 0x11E000):
            continue
        size = None
        for op in ins.operands:
            if op.type == 3 and op.mem.base == 41:
                size = op.size
        if size != 4:
            continue
        key = t
        cands.setdefault(key, []).append((name, irva, ins.mnemonic, ins.op_str))
        if shown < 10:
            print(f"  +0x{irva:X}  {ins.mnemonic:<8} {ins.op_str:<45} -> ci+0x{t:X}")
            shown += 1

print("\n=== 候选全局（按引用次数排序）===")
for t, refs in sorted(cands.items(), key=lambda kv: -len(kv[1])):
    print(f"  ci+0x{t:X}  被引用 {len(refs)} 次   例: {refs[0][0]} @ +0x{refs[0][1]:X}  {refs[0][2]} {refs[0][3]}")
