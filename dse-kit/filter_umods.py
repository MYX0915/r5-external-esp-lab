import re
lines=open(r'C:\ProgramData\umods.txt',errors='ignore').read().splitlines()
print(f"共 {len(lines)} 个模块\n")
common=('kernel32','kernelbase','ntdll','user32','gdi32','advapi32','msvcrt','ucrtbase','rpcrt4',
'combase','ole32','oleaut32','shell32','shlwapi','ws2_32','crypt32','sechost','bcrypt','d3d',
'dxgi','winmm','version','imm32','setupapi','cfgmgr32','win32u','msvcp','vcruntime','api-ms',
'ext-ms','clbcatq','wintrust','imagehlp','dbghelp','psapi','iphlpapi','dnsapi','mswsock',
'ncrypt','powrprof','profapi','secur32','sspicli','twinapi','wldp','xpsobjectmodel','windowscodecs')
def is_common(n):
    n=n.lower()
    return any(n.startswith(c) or c in n for c in common)
other=[]
for L in lines:
    m=re.match(r'^(\S+)\s+base=0x([0-9A-F]+)\s+size=0x([0-9A-F]+)', L.strip())
    if not m: continue
    name,b,s=m.group(1),int(m.group(2),16),int(m.group(3),16)
    if not is_common(name): other.append((name,b,s))
print("=== 非系统组件（可疑候选）===")
for n,b,s in other:
    print(f"   {n:<44} base=0x{b:012X} size=0x{s:X}")
