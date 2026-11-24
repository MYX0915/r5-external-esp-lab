import glob, os, re
base=0x4924D00
hexv="%X"%base
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x200], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
print("?????????>=4?:")
for m in re.finditer(rb'[ -~]{4,}', raw):
    print("  +0x%03X  %s" % (m.start(), m.group().decode('latin1')))
