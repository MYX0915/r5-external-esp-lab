import capstone, re, struct
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.skipdata=True
T=0x226CDE0
# ?????
i=T
while i>T-0x200:
    if text[i-RVA0]==0xCC and text[i-RVA0-1]==0xCC:
        break
    i-=1
print("0x226CDE0 ?? CC ??: 0x%X" % (i+1))
# ???? 0x120 ??
print("\n=== 0x%X ?? 30 ? ===" % T)
n=0
for ins in md.disasm(text[T-RVA0:T-RVA0+0x120], T):
    print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    n+=1
    if n>30: break
# ??????
calls=[]
for p in range(0,len(text)-5):
    if text[p]!=0xE8: continue
    rel=struct.unpack_from("<i", text, p+1)[0]
    if RVA0+p+5+rel==T: calls.append(RVA0+p)
print("\n?? 0x%X ???: %d" % (T,len(calls)))
for c in calls[:6]: print("   0x%08X" % c)
