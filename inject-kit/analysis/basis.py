import struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=struct.unpack_from("<3f",f,8); ang=struct.unpack_from("<3f",f,20)
print("cam=(%.3f,%.3f,%.3f) ang=(%.3f,%.3f)" % (cam[0],cam[1],cam[2],ang[0],ang[1]))
p=math.radians(ang[0]); y=math.radians(ang[1])
rx, ry, rz = math.sin(y), -math.cos(y), 0.0
fx = math.cos(p)*math.cos(y); fy = math.cos(p)*math.sin(y); fz = -math.sin(p)
ux = ry*fz - rz*fy; uy = rz*fx - rx*fz; uz = rx*fy - ry*fx
print("right  = (%.6f,%.6f,%.6f)" % (rx,ry,rz))
print("up     = (%.6f,%.6f,%.6f)" % (ux,uy,uz))
print("fwd    = (%.6f,%.6f,%.6f)" % (fx,fy,fz))
open("basis.txt","w").write("%f %f %f %f %f %f %f %f %f %f %f %f %f %f %f" % (rx,ry,rz,ux,uy,uz,fx,fy,fz,cam[0],cam[1],cam[2],ang[0],ang[1],0.0))
