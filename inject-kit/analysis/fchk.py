import struct, os
p=r"C:\ProgramData\sc_feed.bin"
if not os.path.exists(p): print("feed ???"); raise SystemExit
f=open(p,"rb").read()
if len(f)<64: print("feed ??"); raise SystemExit
cnt=struct.unpack_from("<I",f,44)[0]
me=struct.unpack_from("<3f",f,32)
print("feed count=%d  me=(%.0f,%.0f,%.0f)" % (cnt,me[0],me[1],me[2]))
print("feed ??: %s" % __import__('datetime').datetime.fromtimestamp(os.path.getmtime(p)).strftime('%H:%M:%S'))
