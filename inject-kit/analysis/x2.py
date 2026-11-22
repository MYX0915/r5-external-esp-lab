data = open(r"C:\ProgramData\scdump\15_7FF687CC1000.bin","rb").read()
disp = bytes.fromhex("6C370000")
hits=[]; i=0
while True:
    i = data.find(disp, i)
    if i < 0: break
    hits.append(i); i += 1
print("occurrences of disp32 0x376C:", len(hits))
print("first 15 contexts (8 bytes before, 6 after):")
for h in hits[:15]:
    pre = data[max(0,h-8):h].hex(" ")
    post = data[h+4:h+10].hex(" ")
    print("  RVA 0x%-7X  %-26s [6C 37 00 00] %s" % (h, pre, post))
