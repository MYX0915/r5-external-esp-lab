import struct
from capstone import *
f = open(r"C:\Windows\System32\ntoskrnl.exe","rb").read()
m = open(r"C:\ProgramData\ntoskrnl_mem.bin","rb").read()

# 文件 RVA -> 偏移
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
def r2o(rva):
    for nm,va,vs,rp,rs in secs:
        if va<=rva<va+max(vs,rs): return rp+(rva-va)
    return None

RVA=0xBD72A0
o=r2o(RVA)
print("磁盘文件   :", f[o:o+16].hex(' '))
print("内存镜像   :", m[RVA:RVA+16].hex(' '))
md=Cs(CS_ARCH_X86,CS_MODE_64)
for ins in md.disasm(f[o:o+16], RVA):
    print(f"   文件反汇编 +0x{ins.address:X} {ins.mnemonic} {ins.op_str}")
for ins in md.disasm(m[RVA:RVA+16], RVA):
    print(f"   内存反汇编 +0x{ins.address:X} {ins.mnemonic} {ins.op_str}")
