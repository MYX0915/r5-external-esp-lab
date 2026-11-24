import glob, os, re
fs=sorted(glob.glob(r"C:\ProgramData\scdump\2171_h*.bin"))
print("snap 2171 ?????%d ??:" % len(fs))
regs=[]
for p in fs:
    m=re.search(r'_h\d+_([0-9A-F]+)\.bin$', os.path.basename(p))
    if not m: continue
    base=int(m.group(1),16)
    size=os.path.getsize(p)
    regs.append((base,size))
regs.sort()
for b,s in regs[:12]:
    print("   0x%X ~ 0x%X   %.1f MB" % (b, b+s, s/1048576))
print("   ...")
for b,s in regs[-4:]:
    print("   0x%X ~ 0x%X   %.1f MB" % (b, b+s, s/1048576))
lo=min(b for b,_ in regs); hi=max(b+s for b,s in regs)
print("\n????: 0x%X ~ 0x%X" % (lo,hi))
ent=0x12D101D50
print("??????: 0x%X" % ent)
print("?????: %s" % ("?" if lo<=ent<hi else "? ? ?????????"))
