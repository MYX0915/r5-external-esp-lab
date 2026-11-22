import importlib.util
src = open(r"tools\pe_exports.py").read(); ns={}; exec(src.split("for path in sys.argv")[0], ns)
d, base, secs, rva2off, exp = ns['parse'](r"C:\Windows\System32\ntoskrnl.exe")
for n in ('_vsnprintf','vsnprintf','__C_specific_handler','sprintf','_snprintf'):
    print(f"  {n:<24} {'EXPORTED 0x%X' % exp[n] if n in exp else 'MISSING'}")
