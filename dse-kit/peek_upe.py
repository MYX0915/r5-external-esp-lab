import struct, re
d=open(r'C:\ProgramData\upe_7ED40000.bin','rb').read()
e=struct.unpack_from('<I',d,0x3C)[0]
nsec=struct.unpack_from('<H',d,e+6)[0]; optsz=struct.unpack_from('<H',d,e+20)[0]; opt=e+24
magic=struct.unpack_from('<H',d,opt)[0]
ts=struct.unpack_from('<I',d,e+8)[0]
size_img=struct.unpack_from('<I',d,opt+56)[0]
ep=struct.unpack_from('<I',d,opt+16)[0]
subsys=struct.unpack_from('<H',d,opt+68)[0]
print(f"size={len(d)} magic=0x{magic:X} SizeOfImage=0x{size_img:X} entry=0x{ep:X} ts=0x{ts:08X} subsystem={subsys}")
so=opt+optsz
for i in range(nsec):
    s=so+i*40
    nm=d[s:s+8].rstrip(b'\0').decode('latin1','ignore')
    vs,va,rs,rp=struct.unpack_from('<IIII',d,s+8)
    ch=struct.unpack_from('<I',d,s+36)[0]
    fl=''.join([c for c,m in (('R',0x40000000),('W',0x80000000),('X',0x20000000)) if ch&m])
    print(f"   {nm:<10} va=0x{va:<7X} vs=0x{vs:<7X} flags={fl}")
print("\n字符串:")
for s in re.findall(rb'[\x20-\x7e]{6,}', d)[:20]:
    print("   ", s.decode('ascii','ignore'))
