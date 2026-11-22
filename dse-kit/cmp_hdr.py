import struct
for name, path in (("磁盘", r"C:\Windows\System32\ntoskrnl.exe"), ("内存", r"C:\ProgramData\ntoskrnl_mem.bin")):
    d = open(path,'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    machine, nsec = struct.unpack_from('<HH', d, e+4)
    ts = struct.unpack_from('<I', d, e+8)[0]
    optsz = struct.unpack_from('<H', d, e+20)[0]
    opt = e+24
    size_img = struct.unpack_from('<I', d, opt+56)[0]
    # 节表
    so = opt+optsz
    print(f"{name}: ts=0x{ts:08X} nsec={nsec} SizeOfImage=0x{size_img:X} optsz=0x{optsz:X}")
    for i in range(min(nsec,4)):
        s = so+i*40
        nm = d[s:s+8].rstrip(b'\0').decode('latin1','ignore')
        vs,va,rs,rp = struct.unpack_from('<IIII', d, s+8)
        print(f"    {nm:<8} va=0x{va:<8X} vs=0x{vs:<8X} rawsize=0x{rs:X}")
