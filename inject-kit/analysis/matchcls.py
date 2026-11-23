lines=[l for l in open(r"C:\ProgramData\sc_classes.txt") if l.startswith("0x")]
myvt=int(open("vt.txt").read(),16)
print("our vtable = 0x%X" % myvt)
for l in lines:
    p=l.split()
    if int(p[0],16)==myvt:
        print("  ? ????:", l.strip())
        break
else:
    print("  ? ???????? vtable")
print("\n???? 30~120 ??????????:")
for l in lines:
    p=l.split()
    c=int(p[1])
    if 30<=c<=120: print("   0x%s  %s  %s %s %s" % (p[0][2:], p[1], p[2], p[3], p[4]))
