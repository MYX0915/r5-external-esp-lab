import struct, collections
f = open(r"C:\Windows\System32\ntoskrnl.exe",'rb').read()
m = open(r"C:\ProgramData\ntoskrnl_mem.bin",'rb').read()
e = struct.unpack_from('<I', f, 0x3C)[0]
nsec = struct.unpack_from('<H', f, e+6)[0]
optsz = struct.unpack_from('<H', f, e+20)[0]
opt = e+24
secs=[]; so=opt+optsz
for i in range(nsec):
    s=so+i*40
    nm=f[s:s+8].rstrip(b'\0').decode('latin1','ignore')
    vs,va,rs,rp=struct.unpack_from('<IIII',f,s+8)
    secs.append((nm,va,vs,rp,rs))

for nm,va,vs,rp,rs in secs:
    if nm not in ('.text','PAGE','INIT','PAGELK','PAGEKD','PAGEVRFY'): continue
    chunk=f[rp:rp+rs]
    n=min(vs, len(chunk))
    diffs=[]
    for i in range(n):
        if chunk[i]!=m[va+i]: diffs.append(i)
    if not diffs:
        print(f"{nm:<9} 无差异"); continue
    deltas=collections.Counter((m[va+i]-chunk[i])&0xFF for i in diffs)
    top=deltas.most_common(3)
    print(f"{nm:<9} vs=0x{vs:<8X} 差异={len(diffs):<8} 占比={len(diffs)/n*100:.2f}%  最常见delta={top}")
    if len(diffs)<=6:
        for i in diffs[:6]:
            print(f"     rva=0x{va+i:X} mem={m[va+i]:02x} file={chunk[i]:02x}")
