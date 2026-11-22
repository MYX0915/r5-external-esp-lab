import glob, os, struct
NT=0xFFFFF80790400000
for f in sorted(glob.glob(r'C:\ProgramData\kmod_*.bin')):
    d=open(f,'rb').read()
    if d[:2]!=b'MZ': continue
    e=struct.unpack_from('<I',d,0x3C)[0]
    if d[e:e+4]!=b'PE\0\0': continue
    ts=struct.unpack_from('<I',d,e+8)[0]
    if ts!=0: continue
    optsz=struct.unpack_from('<H',d,e+20)[0]; opt=e+24
    size_img=struct.unpack_from('<I',d,opt+56)[0]
    base=int(os.path.basename(f)[5:-4],16)
    n=min(size_img,len(d))
    pref=0; kern=0; own=0; other=0
    for i in range(0,n-8,8):
        v=struct.unpack_from('<Q',d,i)[0]
        if v==0: continue
        if 0x140000000 <= v < 0x140000000+0x4000000: pref+=1
        elif NT<=v<NT+0x1450000: kern+=1
        elif base<=v<base+size_img: own+=1
        elif 0xFFFFF80000000000<=v<=0xFFFFFFFFFFFFFFFF: other+=1
    print(f"{os.path.basename(f)[5:-4]}  size=0x{size_img:<7X} 自身={own:<5} 0x140xxxxxx={pref:<5} ntoskrnl={kern:<4} 其它内核={other}")
