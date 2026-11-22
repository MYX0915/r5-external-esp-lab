import io
p = r'E:\Users\MYX\Desktop\test-game\inject-kit\overlay\overlay.c'
s = io.open(p, encoding='utf-8', errors='surrogateescape').read()

old_struct = '''typedef struct _FEED {
    unsigned int  magic;
    unsigned int  version;
    float cam[3];
    float ang[3];      /* pitch, yaw, roll (degrees) */
    float pos[3];      /* entity origin */
    float extra[3];
    unsigned long long inst;
    unsigned int  ok;
    unsigned int  pad;
} FEED;'''
new_struct = '''#define FEED_MAX_ENT 24
typedef struct _FEED {
    unsigned int  magic;
    unsigned int  version;
    float cam[3];
    float ang[3];      /* pitch, yaw, roll (degrees) */
    float pos[3];      /* local entity origin */
    unsigned int  count;   /* other players of the same class */
    unsigned int  ok;
    unsigned long long inst;
    float ent[FEED_MAX_ENT][3];
} FEED;'''
assert old_struct in s
s = s.replace(old_struct, new_struct, 1)

# draws: add per-entity boxes
old_draw = '''            } else {
                _snprintf_s(buf, sizeof(buf), _TRUNCATE, "proj off-screen h=%.0f", bh);
                TextOutA(dc, 8, 28, buf, (int)strlen(buf));
            }'''
new_draw = '''            } else {
                _snprintf_s(buf, sizeof(buf), _TRUNCATE, "proj off-screen h=%.0f", bh);
                TextOutA(dc, 8, 28, buf, (int)strlen(buf));
            }
            {   /* other players */
                HPEN ep = CreatePen(PS_SOLID, 2, RGB(255, 80, 80));
                unsigned k;
                SelectObject(dc, ep);
                for (k = 0; k < g_feed.count && k < FEED_MAX_ENT; k++) {
                    float e[3], s1, s2, s3, s4;
                    float top[3];
                    e[0] = g_feed.ent[k][0]; e[1] = g_feed.ent[k][1]; e[2] = g_feed.ent[k][2];
                    top[0] = e[0]; top[1] = e[1]; top[2] = e[2] + (float)g_boxH;
                    if (WorldToScreen(e, w, h, &s1, &s2) && WorldToScreen(top, w, h, &s3, &s4)) {
                        float hgt = s2 - s4;
                        float wid = hgt * (float)g_boxW;
                        if (hgt > 3 && hgt < 4000)
                            Rectangle(dc, (int)(s1 - wid / 2), (int)s4, (int)(s1 + wid / 2), (int)s2);
                    }
                }
                DeleteObject(ep);
            }'''
assert old_draw in s
s = s.replace(old_draw, new_draw, 1)
io.open(p,'w',encoding='utf-8',errors='surrogateescape',newline='').write(s)
print('overlay updated for FEED v3')
