import re
f = r'C:\ProgramData\kmod_FFFFF80366C1C000.bin'
d = open(f,'rb').read()
strs = re.findall(rb'[\x20-\x7e]{6,}', d)
seen = []
for s in strs:
    t = s.decode('ascii')
    if t not in seen:
        seen.append(t)
print(f"unique strings: {len(seen)}")
for t in seen[:60]:
    print("   ", t)
