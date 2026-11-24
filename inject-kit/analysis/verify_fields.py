import struct, glob, os
me=int(open("me_now.txt").read().strip(),16)
names={0x330:"m_iHealth",0x470:"m_iMaxHealth",0x18C:"m_shieldHealth",0x190:"m_shieldHealthMax",0x340:"m_iTeamNum",0x698:"m_lifeState",0x481:"m_iName"}
print("???? 0x%X:" % me)
for off,nm in names.items():
    hexv="%X"%(me+off)
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x8], key=os.path.getmtime)
    if not fs: print("  %-20s ?dump" % nm); continue
    raw=open(fs[-1],"rb").read()
    i=struct.unpack_from("<i",raw,0)[0]
    s=""
    if nm=="m_iName":
        t=raw.split(b'\x00')[0]
        s="  ascii='%s'" % t.decode('latin1')
    print("  %-20s +0x%03X = %d%s" % (nm,off,i,s))
