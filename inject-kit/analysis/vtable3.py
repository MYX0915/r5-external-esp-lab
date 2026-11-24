import math
g,t,v0=725.0,4.0,1500.0
print("\nV=1500 ?????????:")
for d in (20,23,25,28,30,32,35,38,42,45):
    D=d*39.3701
    A=D/t; B=(0+0.5*g*t*t)/t
    reqV=math.hypot(A,B)
    miss=(reqV-v0)*t*0.01905
    flag = "  ???" if abs(miss)<1.0 else ""
    print("  %2dm  reqV=%.0f  miss=%+.1fm%s" % (d,reqV,miss,flag))
