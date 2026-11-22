import struct
m = open(r'C:\ProgramData\ntoskrnl_mem.bin','rb').read()
NT = 0xFFFFF800E2C00000
for rva in (0x117C8, 0x14168, 0x14348, 0x1BE38):
    b = m[rva:rva+32]
    print(f"rva=0x{rva:X}: {b.hex(' ')}")
    # 当作 UNICODE_STRING 解释
    if len(b)>=16:
        ln, mx, ptr = struct.unpack_from('<HHQ', b, 0)
        ok = 0xFFFFF80000000000 <= ptr <= 0xFFFFFFFFFFFFFFFF
        print(f"   UNICODE_STRING? len={ln} max={mx} buf=0x{ptr:X} {'(内核指针)' if ok else ''}")
        if ok and 0 < ln < 200:
            off = ptr - NT
            if 0 <= off < len(m)-ln:
                s = m[off:off+ln].decode('utf-16-le', 'ignore')
                print(f"   字符串: {s!r}")
    asc = ''.join(chr(c) if 32<=c<127 else '.' for c in b)
    if sum(1 for c in b if 32<=c<127) > 20:
        print(f"   ASCII: {asc!r}")
