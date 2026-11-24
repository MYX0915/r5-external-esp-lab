import capstone
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.skipdata=True

# ? 0x226D400 ??? int3 ??????????
i=0x226D400
entry=None
while i>0x226C000:
    if text[i-RVA0]==0xCC and text[i-RVA0-1]==0xCC:
        entry=i+1
        break
    i-=1
print("??????: %s" % ("0x%X"%entry if entry else "???"))

start=entry if entry else 0x226C000
# ?????? 0x226D410
print("\n=== 0x%X ~ 0x226D410 ?? r13/r14/r15/rbx ????? ===" % start)
n=0
for ins in md.disasm(text[start-RVA0:0x226D410-RVA0], start):
    op=ins.op_str
    if ins.mnemonic=="call" or ins.mnemonic=="ret":
        n+=1
    if ("r13" in op) or ("r14" in op) or ("r15" in op):
        print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, op))
print("\n(????? %d ?)" % n)
