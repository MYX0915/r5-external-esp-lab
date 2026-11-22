import struct, re
from capstone import *
IMG=r'C:\ProgramData\kmod_FFFFF800783BA000.bin'
BASE=0xFFFFF800783BA000
d=open(IMG,'rb').read()
e=struct.unpack_from('<I',d,0x3C)[0]
nsec=struct.unpack_from('<H',d,e+6)[0]; optsz=struct.unpack_from('<H',d,e+20)[0]; opt=e+24
secs=[]; so=opt+optsz
for i in range(nsec):
    s=so+i*40
    nm=d[s:s+8].rstrip(b'\0').decode('latin1','ignore')
    vs,va,rs,rp=struct.unpack_from('<IIII',d,s+8)
    secs.append((nm,va,vs,rp,rs))
def r2o(rva):
    for nm,va,vs,rp,rs in secs:
        if va<=rva<va+max(vs,rs): return rp+(rva-va)
    return None
md=Cs(CS_ARCH_X86,CS_MODE_64)
size_img=struct.unpack_from('<I',d,opt+56)[0]
for t in (0x7988,0x8040,0x820c,0x7cc8):
    o=r2o(t)
    if o is None: continue
    print(f"\n=== 目标函数 +0x{t:X} ===")
    n=0
    for ins in md.disasm(d[o:o+0x70], t):
        extra=''
        m=re.search(r'rip \+ (0x[0-9a-f]+)', ins.op_str)
        if m:
            tg=ins.address+ins.size+int(m.group(1),16)
            extra=f'   ; -> +0x{tg:X}'
        m2=re.search(r'(0x[0-9a-f]{10,})', ins.op_str)
        if ins.mnemonic=='movabs' and m2:
            v=int(m2.group(1),16)
            extra=f'   ; abs 0x{v:X}'
        print(f"   +0x{ins.address:X} {ins.mnemonic:<7} {ins.op_str}{extra}")
        n+=1
        if n>18: break
