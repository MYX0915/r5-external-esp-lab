import importlib.util
src = open(r"tools\pe_exports.py").read()
ns = {}
exec(src.split("for path in sys.argv")[0], ns)
d, base, secs, rva2off, exp = ns['parse'](r"C:\Windows\System32\ci.dll")
print("ci.dll exports:", len(exp))
for n, v in sorted(exp.items()):
    print(f"  {n:<40} 0x{v:X}")
