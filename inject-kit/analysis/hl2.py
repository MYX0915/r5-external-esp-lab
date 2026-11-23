import struct
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
base=0x1000
hits=[]
i=0
while True:
    i=text.find(bytes.fromhex("486BC834"), i)
    if i<0: break
    if text[i+4:i+7]==bytes.fromhex("488B05") and text[i+11:i+15]==bytes.fromhex("0FB60C01"):
        disp=struct.unpack_from("<i", text, i+7)[0]
        rva=base+i
        tgt=rva+11+disp
        hits.append((rva,tgt))
    i+=1
print("pattern ??:", len(hits))
for rva,tgt in hits[:10]:
    print("   ?? RVA 0x%-8X ? ??? RVA 0x%X" % (rva,tgt))
