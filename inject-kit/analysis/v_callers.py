import capstone, struct
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
# ??????? 0x2017E5F ??? int3 ??? push
s=0x2017E5F
i=s-1
while i>s-0x200:
    if text[i-RVA0]==0xCC:
        st=i+1
        print("??????(CC ??): 0x%X" % st)
        break
    i-=1
else:
    st=None
    print("??? CC ??")
# ???????
if st:
    print("\n=== ???? ===")
    n=0
    for ins in md.disasm(text[st-RVA0:st-RVA0+0x60], st):
        print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
        n+=1
        if n>14: break
# ??? call ????
targets=set(range(0x2017E00,0x2017E62))
found=[]
for p in range(0,len(text)-5):
    if text[p]!=0xE8: continue
    rel=struct.unpack_from("<i", text, p+1)[0]
    tgt=RVA0+p+5+rel
    if tgt in targets:
        found.append((RVA0+p,tgt))
print("\n=== call ?????????: %d ===" % len(found))
for a,t in found[:12]:
    print("  0x%08X -> 0x%X" % (a,t))
