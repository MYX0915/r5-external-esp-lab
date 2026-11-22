import struct, glob, os
for p in sorted(glob.glob(r"C:\Windows\Minidump\*.dmp"))[-2:]:
    d = open(p, 'rb').read()
    sig = d[:4]; valid = d[4:8]
    code = struct.unpack_from('<I', d, 0x38)[0]
    p1, p2, p3, p4 = struct.unpack_from('<4Q', d, 0x40)
    print(f"{os.path.basename(p)}  sig={sig} valid={valid}  BugCheck=0x{code:X}")
    print(f"   p1=0x{p1:016X} p2=0x{p2:016X} p3=0x{p3:016X} p4=0x{p4:016X}")
