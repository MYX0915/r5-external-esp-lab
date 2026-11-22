import struct, sys

def sections(d):
    nsec = struct.unpack_from('<H', d, 2)[0]
    optsz = struct.unpack_from('<H', d, 16)[0]
    off = 20 + optsz
    out = []
    for i in range(nsec):
        b = off + i * 40
        name = d[b:b + 8].rstrip(b'\0').decode('ascii', 'replace')
        vsize, vaddr, rawsize, rawptr, relptr, lnptr, nrel, nln, chars = struct.unpack_from('<IIIIIIHHI', d, b + 8)
        out.append(dict(name=name, vsize=vsize, rawsize=rawsize, rawptr=rawptr,
                        relptr=relptr, nrel=nrel, chars=chars))
    return out

def symbols(d):
    """flat list indexed exactly like the COFF symbol table (aux records included)"""
    ptr, n = struct.unpack_from('<II', d, 8)
    flat = []
    for i in range(n):
        b = ptr + i * 18
        name8 = d[b:b + 8]
        value, secnum, typ, sclass, naux = struct.unpack_from('<IhHBB', d, b + 8)
        flat.append(dict(name=name8, value=value, sec=secnum, typ=typ, cls=sclass, aux=naux))
    return flat

def apply_relocs(d, text, syms):
    body = bytearray(d[text['rawptr']:text['rawptr'] + text['rawsize']])
    notes = []
    for i in range(text['nrel']):
        b = text['relptr'] + i * 10
        va, symidx, typ = struct.unpack_from('<IIH', d, b)
        # reloc symbol indices are 1-based into the symbol table (as stored)
        s = syms[symidx]
        target = s['value']
        if typ == 0x0004:      # REL32
            cur = struct.unpack_from('<i', body, va)[0]
            new = target - (va + 4) + cur
            struct.pack_into('<i', body, va, new)
            notes.append((va, typ, target, new))
        elif typ == 0x0001:    # ADDR64
            struct.pack_into('<Q', body, va, target)
            notes.append((va, typ, target, target))
        elif typ == 0x0003:    # ADDR32
            struct.pack_into('<I', body, va, target)
            notes.append((va, typ, target, target))
        else:
            notes.append((va, typ, target, None))
    return bytes(body), notes

if __name__ == '__main__':
    obj, outbin = sys.argv[1], sys.argv[2]
    d = open(obj, 'rb').read()
    secs = sections(d)
    text = [s for s in secs if s['name'].startswith('.text')][0]
    syms = symbols(d)
    body, notes = apply_relocs(d, text, syms)
    print(f"text raw=0x{len(body):X} relocs={len(notes)}")
    for va, typ, target, new in notes:
        print(f"   off=0x{va:X} type=0x{typ:X} -> target=0x{target:X} patched={new}")
    for s in syms:
        nm = s['name']
        if s['sec'] == 1 and s['cls'] != 3 and nm[:1] != b'\0':
            print(f"   symbol {nm!r} value=0x{s['value']:X}")
    open(outbin, 'wb').write(body)
    print('wrote', outbin, len(body))
