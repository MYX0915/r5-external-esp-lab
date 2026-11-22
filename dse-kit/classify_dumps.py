import glob, os, struct
for f in sorted(glob.glob(r'C:\ProgramData\kmod_*.bin')):
    d=open(f,'rb').read()
    if d[:2]!=b'MZ': continue
    e=struct.unpack_from('<I',d,0x3C)[0]
    if d[e:e+4]!=b'PE\0\0': continue
    nsec=struct.unpack_from('<H',d,e+6)[0]; optsz=struct.unpack_from('<H',d,e+20)[0]; opt=e+24
    ts=struct.unpack_from('<I',d,e+8)[0]
    size_img=struct.unpack_from('<I',d,opt+56)[0]
    secs=[]; so=opt+optsz
    for i in range(nsec):
        s=so+i*40
        nm=d[s:s+8].rstrip(b'\0').decode('latin1','ignore')
        vs,va,rs,rp=struct.unpack_from('<IIII',d,s+8)
        secs.append((nm,va,vs,rp,rs))
    has_idata=any(s[0]=='.idata' for s in secs)
    # 导入 DLL 名
    dlls=[]
    if has_idata:
        for nm,va,vs,rp,rs in secs:
            if nm!='.idata': continue
            body=d[rp:rp+rs]
            j=0
            while j+20<=len(body):
                nrva,_,_,ft,ot=struct.unpack_from('<IIIII',body,j)
                if nrva==0 and ft==0: break
                for k,va2,vs2,rp2,rs2 in secs:
                    if va2<=nrva<va2+max(vs2,rs2):
                        off=rp2+(nrva-va2)
                        nmz=d[off:d.find(b'\0',off,off+64)].decode('latin1','ignore')
                        if nmz.endswith('.dll') or nmz.endswith('.sys'):
                            dlls.append(nmz)
                        break
                j+=20
    print(f"{os.path.basename(f)[5:-4]}  size=0x{size_img:<7X} ts=0x{ts:08X} idata={'Y' if has_idata else 'N'} dlls={dlls[:4]}")
