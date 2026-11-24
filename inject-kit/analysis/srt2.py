for st in ("0x20","0x30"):
    fn=r"C:\ProgramData\sc_arr_%s.txt"%st
    rows=[l.split() for l in open(fn) if l.startswith("0x")]
    rows=[(int(r[0],16), int(r[1])) for r in rows]
    rows.sort(key=lambda x:-x[1])
    print("=== stride %s : %d ??? ===" % (st,len(rows)))
    for base,run in rows[:8]:
        print("  0x%-10X ?? %3d ?" % (base,run))
    print()
