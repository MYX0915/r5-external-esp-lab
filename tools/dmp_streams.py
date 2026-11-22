import struct
d = open(r'C:\Windows\Minidump\112126-11234-01.dmp','rb').read()
n = struct.unpack_from('<I', d, 0x08)[0]
off = struct.unpack_from('<I', d, 0x0C)[0]
print('streams', n, 'dir', hex(off))
for i in range(n):
    t, sz, rva = struct.unpack_from('<III', d, off + i*12)
    print('  type=%d size=%d rva=0x%X' % (t, sz, rva))
print('dump type @0xF98: 0x%X' % struct.unpack_from('<I', d, 0xF98)[0])
print('dirbase @0x10: 0x%X  psloadedmodules @0x20: 0x%X' % (
    struct.unpack_from('<Q', d, 0x10)[0], struct.unpack_from('<Q', d, 0x20)[0]))
