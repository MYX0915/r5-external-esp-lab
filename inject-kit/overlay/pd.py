import io
p = r'E:\Users\MYX\Desktop\test-game\inject-kit\overlay\overlay.c'
s = io.open(p, encoding='utf-8', errors='surrogateescape').read()
old = '''                        if (hgt > 3 && hgt < 4000)
                            Rectangle(dc, (int)(s1 - wid / 2), (int)s4, (int)(s1 + wid / 2), (int)s2);'''
new = '''                        if (hgt > 3 && hgt < 4000) {
                            double dx = e[0] - g_feed.pos[0];
                            double dy = e[1] - g_feed.pos[1];
                            double dz = e[2] - g_feed.pos[2];
                            double meters = sqrt(dx*dx + dy*dy + dz*dz) * 0.01905;  /* Apex unit -> m */
                            Rectangle(dc, (int)(s1 - wid / 2), (int)s4, (int)(s1 + wid / 2), (int)s2);
                            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%.0fm", meters);
                            TextOutA(dc, (int)(s1 - wid / 2), (int)s4 - 15, buf, (int)strlen(buf));
                        }'''
assert old in s
s = s.replace(old, new, 1)
io.open(p,'w',encoding='utf-8',errors='surrogateescape',newline='').write(s)
print('distance label added')
