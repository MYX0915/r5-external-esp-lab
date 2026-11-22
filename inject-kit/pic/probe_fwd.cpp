#include <windows.h>
#include <cstdio>
int main()
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE kb  = GetModuleHandleA("kernelbase.dll");
    printf("kernel32=%p kernelbase=%p\n", k32, kb);
    BYTE* b = (BYTE*)k32;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(b + ((IMAGE_DOS_HEADER*)b)->e_lfanew);
    DWORD expRva = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    DWORD expSize = nt->OptionalHeader.DataDirectory[0].Size;
    IMAGE_EXPORT_DIRECTORY* e = (IMAGE_EXPORT_DIRECTORY*)(b + expRva);
    printf("export dir rva=0x%X size=0x%X  names=%lu\n", expRva, expSize, e->NumberOfNames);
    const char* want[] = {"CreateFileA","WriteFile","CloseHandle","GetCurrentProcessId"};
    for (int w = 0; w < 4; w++) {
        for (DWORD i = 0; i < e->NumberOfNames; i++) {
            const char* nm = (const char*)(b + ((DWORD*)(b + e->AddressOfNames))[i]);
            if (strcmp(nm, want[w]) == 0) {
                WORD ord = ((WORD*)(b + e->AddressOfNameOrdinals))[i];
                DWORD rva = ((DWORD*)(b + e->AddressOfFunctions))[ord];
                const char* fwd = (rva >= expRva && rva < expRva + expSize) ? (const char*)(b + rva) : nullptr;
                printf("%-20s rva=0x%-6X %s%s\n", want[w], rva, fwd ? "FORWARDER -> " : "code", fwd ? fwd : "");
                break;
            }
        }
    }
    printf("kernelbase!CreateFileA = %p\n", GetProcAddress(kb, "CreateFileA"));
    return 0;
}
