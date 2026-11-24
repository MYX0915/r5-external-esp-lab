import glob, os, collections, datetime
files=glob.glob(r"C:\ProgramData\scdump\*.bin")
print("scdump ????: %d" % len(files))
by_size=collections.Counter(os.path.getsize(f) for f in files)
print("\n?????:")
for s,c in sorted(by_size.items()):
    print("   %8d ?? (0x%X): %d ?" % (s,s,c))

# ??????/??
import numpy as np
stat=collections.Counter()
zero_list=[]
for f in files:
    try:
        d=np.fromfile(f,dtype=np.uint8)
    except Exception:
        stat['????']+=1; continue
    if len(d)<16: stat['??']+=1; continue
    head=d[:min(256,len(d))]
    if not head.any():
        stat['?256????(???)']+=1
        zero_list.append(f)
    else:
        stat['?256?????(???)']+=1
print("\n?????(?? 256 ????):")
for k,v in stat.items():
    print("   %-22s %d" % (k,v))
print("\n??????(?? 5 ?):")
for f in sorted(zero_list, key=os.path.getmtime)[-5:]:
    t=datetime.datetime.fromtimestamp(os.path.getmtime(f)).strftime('%H:%M:%S')
    print("   %-28s %s" % (os.path.basename(f), t))
