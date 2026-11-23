import struct
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
base=0x1000
for pat in ("486BC834","486B4B34","486BC934","48C1E105","486BC0"):
    n=text.count(bytes.fromhex(pat))
    print("%-10s ?? %d ?" % (pat,n))
print()
# ? 0x34 ???? imul ???????
import re
hits=[]
i=0
seq=bytes.fromhex("486B")
while True:
    i=text.find(seq,i)
    if i<0: break
    if i+4<len(text) and text[i+3]==0x34:
        hits.append((base+i, text[i:i+4].hex()))
    i+=1
print("imul r64,r/m64,0x34 ??:", len(hits))
for rva,h in hits[:10]: print("   0x%X  %s" % (rva,h))
