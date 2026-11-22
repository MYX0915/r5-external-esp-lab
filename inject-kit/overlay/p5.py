import io
p = r'E:\Users\MYX\Desktop\test-game\inject-kit\overlay\overlay.c'
s = io.open(p, encoding='utf-8', errors='surrogateescape').read()

# draw whenever we had a good frame recently, regardless of the current read state
s = s.replace('    if (g_have && g_feed.ok) {',
              '    if (g_lastGood && (GetTickCount() - g_lastGood) < 1500) {', 1)
io.open(p, 'w', encoding='utf-8', errors='surrogateescape', newline='').write(s)
print('draw gating fixed')
