ours = {
 "LocalPlayer":0x3EAC660, "ViewRender":0x5267CC0, "ViewMatrix":0x11A390,
 "NameList":0x95BC1A0, "studioHdr":0xFD0, "m_vecAbsOrigin":0x170,
 "m_viewangle":0x25C8, "camera_origin":0x1F78,
}
theirs = {
 "LocalPlayer":0x2670e18, "ViewRender":0x3fd0430, "ViewMatrix":0x11a390,
 "NameList":0x834e7e0, "studioHdr":0x1000, "m_vecAbsOrigin":0x16c,
 "m_viewangle":0x2618, "camera_origin":0x1fcc,
}
print("%-16s %-12s %-12s %s" % ("field","ours","theirs","verdict"))
for k in ours:
    a,b=ours[k],theirs[k]
    v = "MATCH" if a==b else ("diff %+d" % (a-b))
    print("%-16s 0x%-10X 0x%-10X %s" % (k,a,b,v))
