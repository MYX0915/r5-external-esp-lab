import struct
raw=open(r"C:\ProgramData\scdump\14_7FF687CC0000.bin","rb").read()
e_lfanew=struct.unpack_from("<I", raw, 0x3C)[0]
nsec=struct.unpack_from("<H", raw, e_lfanew+6)[0]
optsz=struct.unpack_from("<H", raw, e_lfanew+20)[0]
base=0x7FF687CC0000
print("sections:", nsec)
off=e_lfanew+24+optsz
for i in range(nsec):
    s=raw[off+i*40: off+(i+1)*40]
    name=s[:8].rstrip(b"\0").decode(errors="replace")
    vsize=struct.unpack_from("<I", s, 8)[0]
    rva=struct.unpack_from("<I", s, 12)[0]
    print("  %-8s rva=0x%-8X vsize=0x%-8X va=0x%X" % (name, rva, vsize, base+rva))
