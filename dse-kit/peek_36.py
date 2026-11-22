import struct, re
f=r'C:\ProgramData\kmod_FFFFF80791850000.bin'
d=open(f,'rb').read()
e=struct.unpack_from('<I',d,0x3C)[0]
nsec=struct.unpack_from('<H',d,e+6)[0]; optsz=struct.unpack_from('<H',d,e+20)[0]; opt=e+24
ts=struct.unpack_from('<I',d,e+8)[0]
size_img=struct.unpack_from('<I',d,opt+56)[0]
ep=struct.unpack_from('<I',d,opt+16)[0]
print(f"size={len(d)} SizeOfImage=0x{size_img:X} ts=0x{ts:08X} entry=0x{ep:X}")
so=opt+optsz
for i in range(nsec):
    s=so+i*40
    nm=d[s:s+8].rstrip(b'\0').decode('latin1','ignore')
    vs,va,rs,rp=struct.unpack_from('<IIII',d,s+8)
    ch=struct.unpack_from('<I',d,s+36)[0]
    fl=''.join([c for c,m in (('R',0x40000000),('W',0x80000000),('X',0x20000000)) if ch&m])
    print(f"   {nm:<10} va=0x{va:<8X} vs=0x{vs:<8X} flags={fl}")
# 关键字符串
keys=['eaac','javelin','Electronic Arts','EAAntiCheat','anticheat','ObRegisterCallbacks',
      'PsSetCreateThreadNotifyRoutine','PsSetLoadImageNotifyRoutine','MmCopyVirtualMemory',
      'NtAllocateVirtualMemory','PsProtectedProcess','.grfn','Themida']
low=d.lower()
hit=[k for k in keys if k.lower().encode() in low]
print("特征字符串:", hit if hit else "无")
strs=[s.decode('ascii','ignore') for s in re.findall(rb'[\x20-\x7e]{8,}', d)]
seen=[]
for s in strs:
    if s not in seen: seen.append(s)
print(f"可读字符串 {len(seen)} 条，前 15 条:")
for s in seen[:15]: print("   ", s)
