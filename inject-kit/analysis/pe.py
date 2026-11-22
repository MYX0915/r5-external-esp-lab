import struct, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF776980000.bin") if os.path.getsize(p)>=0x400]
if not fs: print("no PE header dump"); raise SystemExit
raw=open(max(fs,key=os.path.getmtime),"rb").read()
e_lfanew=struct.unpack_from("<I", raw, 0x3C)[0]
opt=e_lfanew+24
nsec=struct.unpack_from("<H", raw, e_lfanew+6)[0]
sizeopt=struct.unpack_from("<H", raw, e_lfanew+20)[0]
sec=e_lfanew+24+sizeopt
print("sections:", nsec)
for i in range(nsec):
    o=sec+i*40
    name=raw[o:o+8].rstrip(b"\0").decode("latin1")
    vsz,vaddr,rsz,raddr=struct.unpack_from("<IIII", raw, o+8)
    if name in (".rdata",".data"):
        print("  %-8s RVA=0x%-8X VSize=0x%-8X raw=0x%X" % (name,vaddr,vsz,rsz))
