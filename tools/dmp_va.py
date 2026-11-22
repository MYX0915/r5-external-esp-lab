import struct, sys, os

def streams(d):
    n = struct.unpack_from('<I', d, 0x08)[0]
    off = struct.unpack_from('<I', d, 0x0C)[0]
    out = []
    for i in range(n):
        t, sz, rva = struct.unpack_from('<III', d, off + i * 12)
        out.append((t, sz, rva))
    return out

def mem_map(d):
    """returns (list_of_(startva, size, fileoffset), total)"""
    for t, sz, rva in streams(d):
        if t == 9:  # Memory64ListStream
            count = struct.unpack_from('<Q', d, rva)[0]
            base_rva = struct.unpack_from('<Q', d, rva + 8)[0]
            ents = []
            off = rva + 16
            cursor = base_rva
            for i in range(count):
                start, size = struct.unpack_from('<QQ', d, off + i * 16)
                ents.append((start, size, cursor))
                cursor += size
            return ents
    return []

def read_va(d, ents, va, ln):
    for start, size, foff in ents:
        if start <= va and va + ln <= start + size:
            o = foff + (va - start)
            return d[o:o + ln]
    return None

if __name__ == '__main__':
    p = sys.argv[1]
    va = int(sys.argv[2], 16)
    ln = int(sys.argv[3]) if len(sys.argv) > 3 else 64
    d = open(p, 'rb').read()
    code = struct.unpack_from('<I', d, 0x38)[0]
    p1, p2, p3, p4 = struct.unpack_from('<4Q', d, 0x40)
    print(f'dump={os.path.basename(p)} size={len(d)} bugcheck=0x{code:X}')
    print(f'  p1=0x{p1:016X} p2=0x{p2:016X} p3=0x{p3:016X} p4=0x{p4:016X}')
    ents = mem_map(d)
    print(f'  memory ranges={len(ents)}')
    b = read_va(d, ents, va, ln)
    if b is None:
        # try to show neighbouring ranges
        near = sorted(ents, key=lambda e: abs(e[0] - va))[:3]
        print('  VA not present in dump; nearest ranges:')
        for s, sz, fo in near:
            print(f'    0x{s:016X}+0x{sz:X}')
        sys.exit(2)
    print('  bytes:', ' '.join(f'{x:02X}' for x in b))
