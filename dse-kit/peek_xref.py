import struct
m = open(r'C:\ProgramData\ntoskrnl_mem.bin','rb').read()
NT = 0xFFFFF800E2C00000
for rva in (0x1201888, 0x1201890, 0x1201898, 0x12018B0, 0xF04510, 0xFC7CB0):
    s = max(0, rva-0x18)
    b = m[s:rva+0x20]
    print(f"\n=== rva=0x{rva:X} (上下文 0x{s:X}) ===")
    for k in range(0, len(b)-8+1, 8):
        v = struct.unpack_from('<Q', b, k)[0]
        mark = '  <== 命中' if s+k == rva else ''
        tag = ''
        if 0xFFFFF80000000000 <= v <= 0xFFFFFFFFFFFFFFFF:
            tag = f'  (ptr -> 0x{v:X})'
        print(f"   +0x{s+k:X}: {v:#018x}{tag}{mark}")
