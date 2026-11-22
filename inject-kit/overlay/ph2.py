import io
p = r'E:\Users\MYX\Desktop\test-game\inject-kit\overlay\overlay.c'
s = io.open(p, encoding='utf-8', errors='surrogateescape').read()
old = '''                        float hh = bh * 0.16f, hw = bh * 0.12f;
                        HPEN hp2 = CreatePen(PS_SOLID, 2, RGB(255, 60, 60));
                        HPEN oldp = (HPEN)SelectObject(dc, hp2);
                        Rectangle(dc, (int)(hsx - hw), (int)(hsy - hh), (int)(hsx + hw), (int)(hsy + hh));'''
new = '''                        float hh = bh * 0.16f, hw = bh * 0.16f;   /* keep it round */
                        HPEN hp2 = CreatePen(PS_SOLID, 2, RGB(255, 60, 60));
                        HPEN oldp = (HPEN)SelectObject(dc, hp2);
                        Ellipse(dc, (int)(hsx - hw), (int)(hsy - hh), (int)(hsx + hw), (int)(hsy + hh));'''
assert old in s
s = s.replace(old, new, 1)
io.open(p,'w',encoding='utf-8',errors='surrogateescape',newline='').write(s)
print('head -> circle')
