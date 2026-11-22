import io
p = r'E:\Users\MYX\Desktop\test-game\inject-kit\overlay\overlay.c'
s = io.open(p, encoding='utf-8', errors='surrogateescape').read()
old = '''    case WM_PAINT: {
        PAINTSTRUCT ps; RECT rc; HBRUSH key;
        HDC dc = BeginPaint(hwnd, &ps);
        GetClientRect(hwnd, &rc);
        key = CreateSolidBrush(KEYCOLOR);
        FillRect(dc, &rc, key);
        DeleteObject(key);
        Draw(dc, rc.right, rc.bottom);
        EndPaint(hwnd, &ps);
        return 0;
    }'''
new = '''    case WM_PAINT: {
        PAINTSTRUCT ps; RECT rc; HBRUSH key;
        HDC dc = BeginPaint(hwnd, &ps);
        HDC mem; HBITMAP bmp, oldBmp;
        GetClientRect(hwnd, &rc);
        mem = CreateCompatibleDC(dc);                       /* double buffer: no flicker */
        bmp = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
        oldBmp = (HBITMAP)SelectObject(mem, bmp);
        key = CreateSolidBrush(KEYCOLOR);
        FillRect(mem, &rc, key);
        DeleteObject(key);
        Draw(mem, rc.right, rc.bottom);
        BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
        SelectObject(mem, oldBmp);
        DeleteObject(bmp);
        DeleteDC(mem);
        EndPaint(hwnd, &ps);
        return 0;
    }'''
assert old in s
s = s.replace(old, new, 1)
io.open(p, 'w', encoding='utf-8', errors='surrogateescape', newline='').write(s)
print('double buffering added')
