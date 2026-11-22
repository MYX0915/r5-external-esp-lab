import struct, glob, os
files = sorted(glob.glob(r"C:\Windows\Minidump\*.dmp"), key=os.path.getmtime)[-3:]
for p in files:
    d = open(p, 'rb').read()
    code = struct.unpack_from('<I', d, 0x38)[0]
    p1, p2, p3, p4 = struct.unpack_from('<4Q', d, 0x40)
    print(f"{os.path.basename(p)}  mtime={__import__('datetime').datetime.fromtimestamp(os.path.getmtime(p)):%H:%M:%S}  BugCheck=0x{code:X}")
    print(f"   p1=0x{p1:016X} p2=0x{p2:016X} p3=0x{p3:016X} p4=0x{p4:016X}")
