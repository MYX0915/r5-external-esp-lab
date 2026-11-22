import struct
d = open(r'C:\Windows\Minidump\112126-11234-01.dmp','rb').read()
i = d.find(b'MDMP')
print('MDMP at', hex(i) if i>=0 else 'none')
if i >= 0:
    ver, n, dirrva = struct.unpack_from('<III', d, i+4)
    print('version=%d streams=%d dir=0x%X' % (ver, n, dirrva))
    for k in range(n):
        t, sz, rva = struct.unpack_from('<III', d, i+dirrva+k*12)
        print('  type=%d size=%d rva=0x%X' % (t, sz, rva))
