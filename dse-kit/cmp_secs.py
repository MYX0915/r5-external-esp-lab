import struct
f = open(r"C:\Windows\System32\ntoskrnl.exe",'rb').read()
m = open(r"C:\ProgramData\ntoskrnl_mem.bin",'rb').read()
e = struct.unpack_from('<I', f, 0x3C)[0]
nsec = struct.unpack_from('<H', f, e+6)[0]
optsz = struct.unpack_from('<H', f, e+20)[0]
opt = e+24
secs=[]
so = opt+optsz
for i in range(nsec):
    s=so+i*40
    nm=f[s:s+8].rstrip(b'\0').decode('latin1','ignore')
    vs,va,rs,rp=struct.unpack_from('<IIII',f,s+8)
    secs.append((nm,va,vs,rp,rs))
def r2o(rva):
    for nm,va,vs,rp,rs in secs:
        if va<=rva<va+max(vs,rs): return rp+(rva-va)
    return None
for nm,va,vs,rp,rs in secs: print(f"  {nm:<8} va=0x{va:<8X} vs=0x{vs:<8X} raw=0x{rp:<8X} rs=0x{rs:X}")
print()
for rva in (0x1000, 0x249380, 0x9472B0):
    o = r2o(rva)
    print(f"RVA 0x{rva:X}: mem={m[rva:rva+8].hex(' ')}  file={f[o:o+8].hex(' ')}")
