rows=[l.split() for l in open(r"C:\ProgramData\sc_arr.txt") if l.startswith("0x")]
rows=[(int(r[0],16), int(r[1]), int(r[2])) for r in rows]
rows.sort(key=lambda x: -x[1])
print("stride 0x40 ????????????:")
for base,run,cnt in rows[:15]:
    print("  0x%-10X ?? %3d ?" % (base, run))
print("\n?? %d ???" % len(rows))
