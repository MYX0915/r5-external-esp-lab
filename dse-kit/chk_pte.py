src=open(r"E:\Users\MYX\Desktop\test-game\tools\pe_exports.py").read()
ns={}; exec(src.split("for path in sys.argv")[0],ns)
d,base,secs,rva2off,exp=ns['parse'](r"C:\Windows\System32\ntoskrnl.exe")
for n in ('MmPteBase','MmPdeBase','MmPpeBase','MmPml4Teb','MiGetPteAddress','MiGetPdeAddress',
          'MmProtectMdlSystemAddress','MmIsAddressValid','MmGetPhysicalAddress'):
    print(f"  {n:<30} {'导出 0x%X'%exp[n] if n in exp else '未导出'}")
