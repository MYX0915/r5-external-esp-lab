#include <windows.h>
#include <cstdio>
int main(int argc, char** argv)
{
    const char* bin = argc > 1 ? argv[1] : "..\\bin\\pic.bin";
    FILE* f = nullptr;
    if (fopen_s(&f, bin, "rb") != 0 || !f) { printf("open %s failed\n", bin); return 1; }
    unsigned char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    printf("blob=%zu bytes\n", n);

    void* mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { printf("alloc failed\n"); return 2; }
    memcpy(mem, buf, n);
    FlushInstructionCache(GetCurrentProcess(), mem, n);

    typedef void (*fn_t)(void);
    printf("calling %p ...\n", mem);
    ((fn_t)mem)();
    printf("returned, pid=%lu\n", GetCurrentProcessId());
    Sleep(100);
    return 0;
}
