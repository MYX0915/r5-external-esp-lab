import importlib.util
src = open(r"tools\pe_exports.py").read()
ns = {}
exec(src.split("for path in sys.argv")[0], ns)
d, base, secs, rva2off, exp = ns['parse'](r"C:\Windows\System32\ntoskrnl.exe")
for pat in ('CreateThreadEx','RtlCreateUserThread','PsCreateSystemThread','NtCreateThread','ZwCreateThread'):
    hits=[(n,hex(v)) for n,v in exp.items() if pat in n]
    print(pat, hits)
