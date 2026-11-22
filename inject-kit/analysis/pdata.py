import struct, bisect
pdata=open(r"C:\ProgramData\scdump\18_7FF695B30000.bin","rb").read()
n=len(pdata)//12
ents=[]
for i in range(n):
    b,e,u=struct.unpack_from("<III",pdata,i*12)
    if b: ents.append((b,e))
ents.sort()
print("RUNTIME_FUNCTION entries:", len(ents))
begins=[e[0] for e in ents]
def find(rva):
    i=bisect.bisect_right(begins, rva)-1
    if i>=0 and ents[i][0] <= rva < ents[i][1]:
        return ents[i]
    return None
for rva in (0x23FF631, 0x2081162):
    r=find(rva)
    print("RVA 0x%X -> function 0x%X..0x%X (%d bytes), offset in func = 0x%X" %
          (rva, r[0], r[1], r[1]-r[0], rva-r[0]) if r else "0x%X -> not found" % rva)
