import glob, os, re
KEY = [b'eaanticheat', b'javelin', b'Electronic Arts', b'EAAntiCheat', b'EAAC',
       b'ObRegisterCallbacks', b'PsSetCreateThreadNotifyRoutine', b'PsSetLoadImageNotifyRoutine',
       b'MmCopyVirtualMemory', b'PspCreateThread', b'NtAllocateVirtualMemory']
rows=[]
for f in sorted(glob.glob(r'C:\ProgramData\kmod_*.bin')):
    d=open(f,'rb').read(); low=d.lower()
    hits=[k.decode() for k in KEY if k.lower() in low]
    if hits: rows.append((os.path.basename(f), len(d), hits))
if not rows:
    print("28 个 dump 里没有任何 EA/回调相关字符串（全部加壳或无关）")
else:
    for n,sz,h in rows:
        print(f"{n}  {sz}B  HITS: {', '.join(h)}")
