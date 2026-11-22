import struct
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
TARGETS={0x23FEE73}   # function start
hits=[]
for i in range(len(text)-5):
    if text[i]!=0xE8: continue
    rel=struct.unpack_from("<i", text, i+1)[0]
    rva=0x1000+i
    tgt=rva+5+rel
    if tgt in TARGETS:
        hits.append((rva,tgt))
print("direct calls to 0x23FEE73:", len(hits))
for rva,t in hits[:10]:
    print("   call at 0x%X" % rva)
