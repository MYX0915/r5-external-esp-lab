import glob, os, struct
from capstone import *
m = open(r'C:\ProgramData\ntoskrnl_mem.bin','rb').read()
# 真实内存里的 ntoskrnl 基址（日志）
base = None
import re
for line in open(r'C:\ProgramData\kmaplog.txt',errors='ignore'):
    t = re.search(r'\[ntdump\] ntoskrnl base=0x([0-9A-F]+)', line)
    if t: base = int(t.group(1),16)
if base is None:
    base = 0xFFFFF800E2C00000
print(f"ntoskrnl base=0x{base:X}  镜像长度={len(m)}")

HID=[]
for f in glob.glob(r'C:\ProgramData\kmod_*.bin'):
    d=open(f,'rb').read()
    if d[:2]!=b'MZ': continue
    e=struct.unpack_from('<I',d,0x3C)[0]
    if d[e:e+4]!=b'PE\0\0': continue
    optsz=struct.unpack_from('<H',d,e+20)[0]
    sz=struct.unpack_from('<I',d,e+24+56)[0]
    b=int(os.path.basename(f)[5:-4],16)
    HID.append((b,b+min(sz,len(d)),os.path.basename(f),f))
HID.sort()

def owner(v):
    for b,e2,n,f in HID:
        if b<=v<e2: return n,f,v-b
    return None

# 只扫 .rdata + .data 这两个"指针表区域"，减少噪声
hits={}
for i in range(0,len(m)-8):
    v=struct.unpack_from('<Q',m,i)[0]
    if not (0xFFFFF80000000000 <= v <= 0xFFFFFFFFFFFFFFFF): continue
    o=owner(v)
    if o: hits.setdefault(o[0],[]).append((i,o[2]))

top=sorted(hits.items(), key=lambda kv:-len(kv[1]))[:4]
for name,lst in top:
    print(f"\n=== {name}: {len(lst)} 处 ===")
    rvas=[r for r,_ in lst]
    print(f"  ntoskrnl rva 范围: 0x{min(rvas):X} ~ 0x{max(rvas):X}")
    # 打印数组前 6 项原始内容
    r0=min(rvas)
    print("  数组内容（每 0x18 字节一项）:")
    for k in range(6):
        off=r0+k*0x18
        chunk=m[off:off+0x18]
        q=struct.unpack_from('<QQQ',chunk,0)
        print(f"    rva=0x{off:X}: {q[0]:#018x} {q[1]:#018x} {q[2]:#018x}")
    # 目标偏移的反汇编
    tgts=[o for _,o in lst[:3]]
    f=[x[3] for x in HID if x[2]==name][0]
    img=open(f,'rb').read()
    e=struct.unpack_from('<I',img,0x3C)[0]
    optsz=struct.unpack_from('<H',img,e+20)[0]
    opt=e+24
    nsec=struct.unpack_from('<H',img,e+6)[0]
    secs=[]
    so=opt+optsz
    for i2 in range(nsec):
        s=so+i2*40
        nm=img[s:s+8].rstrip(b'\0').decode('latin1','ignore')
        vs,va,rs,rp=struct.unpack_from('<IIII',img,s+8)
        secs.append((nm,va,vs,rp,rs))
    def r2o(rva):
        for nm,va,vs,rp,rs in secs:
            if va<=rva<va+max(vs,rs): return rp+(rva-va)
        return None
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    for t in tgts[:2]:
        o2=r2o(t)
        if o2 is None: continue
        print(f"  目标 +0x{t:X} 附近反汇编:")
        for ins in md.disasm(img[o2:o2+32], t):
            print(f"     +0x{ins.address:X} {ins.mnemonic} {ins.op_str}")
