import io
p = r'E:\Users\MYX\Desktop\test-game\inject-kit\overlay\overlay.c'
s = io.open(p, encoding='utf-8', errors='surrogateescape').read()
# reload config every second from the timer
s = s.replace('''        if (now - last >= 1000) { g_fps = frames; frames = 0; last = now; }''',
'''        if (now - last >= 1000) { g_fps = frames; frames = 0; last = now; LoadConfig(); }''', 1)
io.open(p, 'w', encoding='utf-8', errors='surrogateescape', newline='').write(s)
print('live config reload added')
