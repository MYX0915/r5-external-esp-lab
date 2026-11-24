import capstone, re
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.skipdata=True
# ?????????? 0x226DB32 ??? CC ??
i=0x226DB32
entry=None
while i>0x226C000:
    if text[i-RVA0]==0xCC and text[i-RVA0-1]==0xCC:
        entry=i+1; break
    i-=1
print("??????: %s" % ("0x%X"%entry if entry else "???"))
start=entry or 0x226C000
print("???? 0x%X ~ 0x226DB80???? [rsp+0x2090..] ??? ? r12 ??\n" % start)
hits=[]
r12hits=[]
for ins in md.disasm(text[start-RVA0:0x226DB80-RVA0], start):
    op=ins.op_str
    if "0x2090" in op or "0x2092" in op or "0x2094" in op:
        hits.append(ins)
    if ins.mnemonic in ("mov","lea","add") and op.startswith("r12,"):
        r12hits.append(ins)
print("=== ?? 0x2090 ?????: %d ===" % len(hits))
for ins in hits[:14]:
    print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
print("\n=== r12 ??: %d ===" % len(r12hits))
for ins in r12hits[:10]:
    print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
