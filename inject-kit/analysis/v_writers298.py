import capstone, struct
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
disp=bytes.fromhex("98020000")   # 0x298 ??
raw=b"\x98\x02\x00\x00"
hits=[]
pos=0
while True:
    p=text.find(raw,pos)
    if p<0: break
    pos=p+1
    # ??? p-8..p-1 ???????????? disp ???
    for back in range(1,10):
        s=p-back
        if s<0: continue
        try:
            ins=next(md.disasm(text[s:s+16], RVA0+s))
        except StopIteration:
            continue
        if ins.size==back+4 and ("+ 0x298" in ins.op_str or "+ 0x298]" in ins.op_str):
            hits.append((ins.address,ins.bytes.hex(),ins.mnemonic+" "+ins.op_str))
            break
print("?? +0x298 ?????: %d" % len(hits))
WRITE=("mov","add","sub","inc","dec","or","and","xor","bts","btr","set","xchg")
w=[h for h in hits if (h[2].split()[0] in WRITE) and ("ptr [" in h[2]) and ("[r" in h[2]) and (h[2].split("[")[1].split(",")[0].strip().startswith("r") or True)]
# ???: ???????? = ??
def is_write(op):
    parts=op[2].split(None,1)
    if len(parts)<2: return False
    dst=parts[1].split(",")[0]
    return "ptr [" in dst and "+ 0x298" in dst
w=[h for h in hits if is_write(h)]
r=[h for h in hits if not is_write(h)]
print("  ????(????): %d" % len(w))
print("  ????/??: %d" % len(r))
print("\n--- ?? +0x298 ????? ---")
for a,b,o in w[:40]:
    print("  0x%08X  %-20s %s" % (a,b,o))
