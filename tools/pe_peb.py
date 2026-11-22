import sys, importlib.util
spec = importlib.util.spec_from_file_location("pe", r"tools\pe_exports.py")
# 直接复用解析逻辑：手工调用 parse()
src = open(r"tools\pe_exports.py").read()
ns = {}
exec(src.split("for path in sys.argv")[0], ns)
d, base, secs, rva2off, exp = ns['parse'](r"C:\Windows\System32\ntoskrnl.exe")
hits = [ (n,hex(v)) for n,v in exp.items() if 'Peb' in n ]
print('\n'.join(f'{n} {v}' for n,v in hits))
