import struct, glob, os, numpy as np, time
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=struct.unpack_from("<3f",f,8); ang=struct.unpack_from("<3f",f,20); pos=struct.unpack_from("<3f",f,32)
cnt=struct.unpack_from("<I",f,44)[0]
print("cam=(%.1f,%.1f,%.1f)" % cam)
print("pos=(%.1f,%.1f,%.1f)" % pos)
print("count=%d ang=(%.1f,%.1f)" % (cnt,ang[0],ang[1]))
print("feed ????:", time.strftime('%H:%M:%S', time.localtime(os.path.getmtime(r"C:\ProgramData\sc_feed.bin"))))
print("??:", time.strftime('%H:%M:%S'))
