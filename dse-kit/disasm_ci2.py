import importlib.util
from capstone import *
src = open(r"tools\pe_exports.py").read()
ns = {}; exec(src.split("for path in sys.argv")[0], ns)
d, base, secs, rva2off, exp = ns['parse'](r"C:\Windows\System32\ci.dll")
off = rva2off(exp['CiInitialize'])
code = d[off:off+0x80]
md = Cs(CS_ARCH_X86, CS_MODE_64)
for i, ins in enumerate(md.disasm(code, 0x140000000 + exp['CiInitialize'])):
    print(f"  {ins.mnemonic:<8} {ins.op_str}")
    if i > 18: break
