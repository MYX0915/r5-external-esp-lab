import struct
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
base=0x1000  # ?????? RVA 0x1000
pat=bytes.fromhex("486BC8344 88B05".replace(" ",""))
# ???"48 6B C8 34" + "48 8B 05" + ?? ?? ?? ?? + "0F B6 0C 01"
head=bytes.fromhex("486BC834")
mid =bytes.fromhex("488B05")
tail=bytes.fromhex("0FB60C01")
hits=[]
i=0
while True:
    i=text.find(head,i)
    if i<0: break
    if text[i+6:i+8]==mid and text[i+12:i+16]==tail:
        disp=struct.unpack_from("<i", text, i+8)[0]
        rva=base+i
        tgt=rva+12+disp      # mov rax,[rip+X] ?? i+6???7????? i+13? ???
        hits.append((rva,disp))
    i+=1
print("pattern ??:", len(hits))
for rva,disp in hits[:10]:
    print("   RVA 0x%X  disp=0x%X" % (rva,disp))
