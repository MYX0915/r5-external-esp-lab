import importlib.util
src = open(r"tools\pe_exports.py").read()
ns = {}
exec(src.split("for path in sys.argv")[0], ns)
d, base, secs, rva2off, exp = ns['parse'](r"C:\Windows\System32\ntoskrnl.exe")
for pat in ('SeValidateImage','CiValidate','MmLoadSystemImage','SeCiCallbacks','g_Ci'):
    hits = [(n, hex(v)) for n, v in exp.items() if pat.lower() in n.lower()]
    print(f"{pat:<20} {hits}")
