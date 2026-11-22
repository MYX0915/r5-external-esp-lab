import io
p = r'E:\Users\MYX\Desktop\test-game\inject-kit\overlay\overlay.c'
s = io.open(p, encoding='utf-8', errors='surrogateescape').read()

old = '''            if (bh > 4 && bh < 4000) {
                Rectangle(dc, (int)(sx - bw / 2), (int)sy2, (int)(sx + bw / 2), (int)sy);'''
new = '''            if (bh > 4 && bh < 4000) {
                Rectangle(dc, (int)(sx - bw / 2), (int)sy2, (int)(sx + bw / 2), (int)sy);
                {   /* head marker: feet + eye height, no bones needed */
                    float hp[3];
                    float hsx, hsy;
                    hp[0] = feet[0]; hp[1] = feet[1]; hp[2] = feet[2] + (float)g_boxH;
                    if (WorldToScreen(hp, w, h, &hsx, &hsy)) {
                        float hh = bh * 0.16f, hw = bh * 0.12f;
                        HPEN hp2 = CreatePen(PS_SOLID, 2, RGB(255, 60, 60));
                        HPEN oldp = (HPEN)SelectObject(dc, hp2);
                        Rectangle(dc, (int)(hsx - hw), (int)(hsy - hh), (int)(hsx + hw), (int)(hsy + hh));
                        SelectObject(dc, oldp);
                        DeleteObject(hp2);
                    }
                }'''
assert old in s
s = s.replace(old, new, 1)
io.open(p,'w',encoding='utf-8',errors='surrogateescape',newline='').write(s)
print('head marker added')
