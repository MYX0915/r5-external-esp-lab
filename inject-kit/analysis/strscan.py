import glob, os, re
me=int(open("me.txt").read().strip(),16)
hexv="%X"%me
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x3000], key=os.path.getmtime)
if not fs: print("?dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
print("???????>=4?:")
n=0
for m in re.finditer(rb'[ -~]{4,}', raw):
    s=m.group().decode('latin1')
    print("  +0x%04X  %s" % (m.start(), s))
    n+=1
    if n>=25: break
