import struct, glob, os
m=open(r'C:\ProgramData\ntoskrnl_mem.bin','rb').read()
NT=0xFFFFF800E2C00000
# ntoskrnl 导出表（rva -> name）
e=struct.unpack_from('<I',m,0x3C)[0]; opt=e+24
exp_rva,_=struct.unpack_from('<II',m,opt+0x70)
nn=struct.unpack_from('<I',m,exp_rva+0x18)[0]
af,an,ao=struct.unpack_from('<III',m,exp_rva+0x1C)
exp={}
for i in range(nn):
    nr=struct.unpack_from('<I',m,an+i*4)[0]
    nm=m[nr:m.find(b'\0',nr)].decode('latin1','ignore')
    oi=struct.unpack_from('<H',m,ao+i*2)[0]
    fr=struct.unpack_from('<I',m,af+oi*4)[0]
    exp.setdefault(fr,nm)
print(f"ntoskrnl 导出 {len(exp)} 个")

IMG=r'C:\ProgramData\kmod_FFFFF800783BA000.bin'
d=open(IMG,'rb').read()
e2=struct.unpack_from('<I',d,0x3C)[0]; opt2=e2+24
nsec=struct.unpack_from('<H',d,e2+6)[0]; optsz=struct.unpack_from('<H',d,e2+20)[0]
secs=[]; so=opt2+optsz
for i in range(nsec):
    s=so+i*40
    nm=d[s:s+8].rstrip(b'\0').decode('latin1','ignore')
    vs,va,rs,rp=struct.unpack_from('<IIII',d,s+8)
    secs.append((nm,va,vs,rp,rs))
size_img=struct.unpack_from('<I',d,opt2+56)[0]
img=bytearray(size_img)
for nm,va,vs,rp,rs in secs:
    n=min(vs,rs,size_img-va)
    if n>0: img[va:va+n]=d[rp:rp+n]

hits={}
for i in range(0,size_img-8):
    v=struct.unpack_from('<Q',img,i)[0]
    if NT<=v<NT+0x1450000:
        rva=v-NT
        nm=exp.get(rva)
        if nm: hits.setdefault(nm,[]).append((i,rva))
print(f"\n模块内指向 ntoskrnl **导出函数** 的指针: {sum(len(v) for v in hits.values())} 处 / {len(hits)} 个 API")
for nm,lst in sorted(hits.items(), key=lambda kv:-len(kv[1])):
    print(f"   {nm:<34} {len(lst)} 处  (模块内 +0x{lst[0][0]:X})")
