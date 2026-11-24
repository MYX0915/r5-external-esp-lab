import struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=struct.unpack_from("<3f",f,8)
ang=struct.unpack_from("<2f",f,20)
me=struct.unpack_from("<3f",f,32)
tx,ty,tz=( -7162.0,-1662.0,228.0 )
dx,dy,dz=tx-me[0],ty-me[1],tz-me[2]
dist=math.sqrt(dx*dx+dy*dy+dz*dz)
bearing=math.degrees(math.atan2(dy,dx))
yaw=math.degrees(ang[1])
rel=(bearing-yaw+540)%360-180
print("??? = (%.0f,%.0f,%.0f)  ??yaw=%.1f?" % (me[0],me[1],me[2],yaw))
print("???? = %.1f?  ?? %.1f m" % (bearing, dist*0.01905))
print("?????: %+.1f?  ?  %s" % (rel, "?" if rel>0 else "?"))
print("??: ????? %.0f ?? (%.0f m)" % (dz, dz*0.01905))
