import struct, os
PAIRS=[('udll_ntdll.dll.bin', r'C:\Windows\System32\ntdll.dll',
        ['NtAllocateVirtualMemory','NtProtectVirtualMemory','NtMapViewOfSection','LdrLoadDll']),
       ('udll_kernel32.dll.bin', r'C:\Windows\System32\kernel32.dll',
        ['LoadLibraryW','LoadLibraryExW','VirtualAlloc','VirtualProtect'])]
def parse(d):
    e=struct.unpack_from('<I',d,0x3C)[0]; nsec=struct.unpack_from('<H',d,e+6)[0]
    optsz=struct.unpack_from('<H',d,e+20)[0]; opt=e+24
    secs=[]; so=opt+optsz
    for i in range(nsec):
        s=so+i*40
        nm=d[s:s+8].rstrip(b'\0').decode('latin1','ignore')
        vs,va,rs,rp=struct.unpack_from('<IIII',d,s+8)
        secs.append((nm,va,vs,rp,rs))
    exp_rva,_=struct.unpack_from('<II',d,opt+0x70)
    return secs,exp_rva
def r2o(secs,rva):
    for nm,va,vs,rp,rs in secs:
        if va<=rva<va+max(vs,rs): return rp+(rva-va)
    return None
def exps(d,secs,er):
    out={}
    if not er: return out
    nn=struct.unpack_from('<I',d,er+0x18)[0]; af,an,ao=struct.unpack_from('<III',d,er+0x1C)
    for i in range(nn):
        nr=struct.unpack_from('<I',d,an+i*4)[0]
        nm=d[nr:d.find(b'\0',nr,nr+128)].decode('latin1','ignore')
        oi=struct.unpack_from('<H',d,ao+i*2)[0]
        out[nm]=struct.unpack_from('<I',d,af+oi*4)[0]
    return out
print("条目格式: { \"name\", rva, {orig bytes} }")
for memn,disk,apis in PAIRS:
    mem=open(os.path.join(r'C:\ProgramData',memn),'rb').read()
    dsk=open(disk,'rb').read()
    ms,mer=parse(mem); ds,der=parse(dsk)
    me=exps(mem,ms,mer); de=exps(dsk,ds,der)
    print(f"\n// {disk}")
    for a in apis:
        if a not in me or a not in de: print(f"//  {a} 缺失"); continue
        rva=me[a]
        mo=r2o(ms,rva); do=r2o(ds,rva)     # 用内存的 RVA 去磁盘取同位置
        mb=mem[mo:mo+8]; db=dsk[do:do+8] if do else b''
        print(f"    {{ \"{a}\", 0x{rva:X}, {{ {', '.join('0x%02X'%b for b in db)} }} }},   // mem={mb.hex(' ')} disk={db.hex(' ')}")
