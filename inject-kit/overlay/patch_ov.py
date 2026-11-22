import io
p = r'E:\Users\MYX\Desktop\test-game\inject-kit\overlay\overlay.c'
s = io.open(p, encoding='utf-8', errors='surrogateescape').read()

# no fill + configurable fov
s = s.replace('''    SetBkMode(dc, TRANSPARENT);
    SelectObject(dc, pen);''',
'''    SetBkMode(dc, TRANSPARENT);
    SelectObject(dc, pen);
    SelectObject(dc, GetStockObject(NULL_BRUSH));   /* outline only, no fill */''', 1)

# fov from ini
s = s.replace('static double g_fps;', 'static double g_fps;\nstatic double g_fov = 90.0;\nstatic double g_boxH = 72.0;\nstatic double g_boxW = 0.42;', 1)
s = s.replace('    double f, fovh = 90.0;', '    double f, fovh = g_fov;', 1)

# loader for ini
s = s.replace('static void Reload(void)', '''static void LoadConfig(void)
{
    char buf[512];
    FILE* f = NULL;
    if (fopen_s(&f, "C:\\\\ProgramData\\\\sc_overlay.ini", "r") != 0 || !f) return;
    while (fgets(buf, sizeof(buf), f)) {
        double v;
        if (sscanf_s(buf, "fov=%lf", &v) == 1 && v > 20 && v < 170) g_fov = v;
        else if (sscanf_s(buf, "boxH=%lf", &v) == 1 && v > 10 && v < 200) g_boxH = v;
        else if (sscanf_s(buf, "boxW=%lf", &v) == 1 && v > 0.1 && v < 2.0) g_boxW = v;
    }
    fclose(f);
}

static void Reload(void)''', 1)
s = s.replace('        head[2] = feet[2] + 72.0f;', '        head[2] = feet[2] + (float)g_boxH;', 1)
s = s.replace('            float bw = bh * 0.45f;', '            float bw = bh * (float)g_boxW;', 1)
s = s.replace('    g_overlay = CreateWindowExW(', '    LoadConfig();\n    g_overlay = CreateWindowExW(', 1)
io.open(p, 'w', encoding='utf-8', errors='surrogateescape', newline='').write(s)
print('overlay patched')
