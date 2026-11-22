import io
p = r'E:\Users\MYX\Desktop\test-game\inject-kit\overlay\overlay.c'
s = io.open(p, encoding='utf-8', errors='surrogateescape').read()
s = s.replace('static int   g_have;', 'static int   g_have;\nstatic FEED  g_last;\nstatic DWORD g_lastGood;', 1)
s = s.replace('''    if (ReadFile(hf, &g_feed, sizeof(g_feed), &got, NULL) && got == sizeof(g_feed) && g_feed.magic == 0x44454546)
        g_have = 1;
    else
        g_have = 0;''',
'''    if (ReadFile(hf, &g_feed, sizeof(g_feed), &got, NULL) && got == sizeof(g_feed) && g_feed.magic == 0x44454546) {
        if (g_feed.ok && g_feed.inst) { g_last = g_feed; g_lastGood = GetTickCount(); }
        else if (g_lastGood && GetTickCount() - g_lastGood < 2000) g_feed = g_last;   /* hold last good frame */
        g_have = 1;
    } else {
        g_have = 0;
    }''', 1)
io.open(p, 'w', encoding='utf-8', errors='surrogateescape', newline='').write(s)
print('hold-last-good added')
