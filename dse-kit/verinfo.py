import re, struct
for f in (r'C:\ProgramData\kmod_FFFFF803D1578000.bin', r'C:\ProgramData\kmod_FFFFF803D26EB000.bin'):
    d = open(f,'rb').read()
    # UTF-16LE 字符串
    txt = d.decode('utf-16-le', errors='ignore')
    keys = ['CompanyName','ProductName','FileDescription','OriginalFilename','LegalCopyright','FileVersion']
    print(f"\n=== {f.split(chr(92))[-1]} ({len(d)}B) ===")
    for k in keys:
        idx = 0; shown = 0
        while shown < 2:
            i = txt.find(k, idx)
            if i < 0: break
            seg = txt[i:i+160]
            m = re.search(r'[\x20-\x7e]{3,}', seg)
            if m: print(f"   {k}: ...{m.group(0)}")
            idx = i + len(k); shown += 1
    # ASCII 公司/产品名
    for k in (b'Electronic Arts', b'EA', b'Microsoft', b'Windows Defender', b'Antimalware'):
        if k.lower() in d.lower(): print(f"   ascii hit: {k.decode()}")
