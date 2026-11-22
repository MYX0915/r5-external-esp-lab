data=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
print("text MB:", round(len(data)/1048576,1))
for name,disp in (("cam 0x1F78","781F0000"), ("cam2 0x1F74","741F0000"), ("pos 0x376C","6C370000")):
    b=bytes.fromhex(disp); hits=[]; i=0
    while True:
        i=data.find(b,i)
        if i<0: break
        hits.append(i); i+=1
    print("%-14s occurrences=%d" % (name, len(hits)))
    for h in hits[:6]:
        print("    RVA 0x%-7X pre=%-22s" % (h, data[max(0,h-10):h].hex(" ")))
