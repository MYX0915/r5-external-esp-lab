import io
p = r'E:\Users\MYX\Desktop\test-game\inject-kit\overlay\overlay.c'
s = io.open(p, encoding='utf-8', errors='surrogateescape').read()
start = s.find('                {   /* head marker: feet + eye height, no bones needed */')
end = s.find('            } else {', start)
assert start > 0 and end > start
s = s[:start] + s[end:]
io.open(p,'w',encoding='utf-8',errors='surrogateescape',newline='').write(s)
print('head circle removed')
