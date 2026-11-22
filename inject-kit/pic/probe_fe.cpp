#include <windows.h>
#include <cstdio>
int main(int argc, char** argv)
{
    FILE* f = nullptr; fopen_s(&f, argc > 1 ? argv[1] : "..\\bin\\pic.bin", "rb");
    unsigned char buf[4096]; size_t n = fread(buf, 1, sizeof(buf), f); fclose(f);
    void* mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(mem, buf, n);
    typedef unsigned long long (*fe_t)(void*, const char*, unsigned);
    fe_t fe = (fe_t)((unsigned char*)mem + 0x1C0);   // placeholder, replaced below
    printf("probe FindExport offset via marks\n");
    // scan for the FindExport prologue pattern: 41 57 41 56 41 55 41 54 57 56 53 48 83 EC
    for (size_t i = 0; i + 16 < n; i++) {
        if (buf[i]==0x41 && buf[i+1]==0x57 && buf[i+2]==0x41 && buf[i+3]==0x56 &&
            buf[i+4]==0x41 && buf[i+5]==0x55 && buf[i+6]==0x41 && buf[i+7]==0x54 &&
            buf[i+8]==0x57 && buf[i+9]==0x56 && buf[i+10]==0x53) { fe = (fe_t)((unsigned char*)mem + i); printf("FindExport at 0x%zX\n", i); break; }
    }
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    const char* names[] = {"CreateFileA","WriteFile","CloseHandle","GetCurrentProcessId"};
    for (int i = 0; i < 4; i++) {
        unsigned long long r = fe(k32, names[i], (unsigned)strlen(names[i]));
        printf("%-20s -> 0x%llX (real %p)\n", names[i], r, GetProcAddress(k32, names[i]));
    }
    return 0;
}
