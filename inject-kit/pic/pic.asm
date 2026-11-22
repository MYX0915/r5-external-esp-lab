; pic.asm -- position independent payload: no PE, no LoadLibrary
;   * finds kernel32 by walking PEB->Ldr
;   * resolves CreateFileA / WriteFile / CloseHandle / GetCurrentProcessId from exports
;   * writes C:\Users\Public\pic-ok.txt  ("PICOK:<pid>\r\n")
;   * returns to whoever called it (KiUserApcDispatcher)
; entry: rsp % 16 == 8 (normal x64 function entry)
OPTION CASEMAP:NONE

_TEXT SEGMENT 'CODE'

PUBLIC PicEntry
PUBLIC FindExport

PicEntry PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 60h

    ; ---- find kernel32 in PEB->Ldr ----
    mov     rax, gs:[60h]           ; PEB
    mov     rax, [rax+18h]          ; PEB->Ldr
    lea     r15, [rax+10h]          ; &InLoadOrderModuleList
    mov     rbx, [r15]              ; first entry
walk:
    cmp     rbx, r15
    je      give_up
    movzx   eax, word ptr [rbx+58h] ; BaseDllName.Length (USHORT!)
    cmp     eax, 18h                ; "kernel32.dll" = 12 wchars
    jne     next_entry
    mov     rsi, [rbx+60h]          ; name buffer
    lea     rdi, name_k32
    mov     ecx, 12
cmp_name:
    mov     dx, [rsi]
    cmp     dx, [rdi]
    jne     next_entry
    add     rsi, 2
    add     rdi, 2
    dec     ecx
    jnz     cmp_name
    jmp     found_k32
next_entry:
    mov     rbx, [rbx]
    jmp     walk
found_k32:
    mov     rbx, [rbx+30h]          ; DllBase
    mov     [rsp+58h], rbx          ; keep base

    ; ---- resolve exports ----
    mov     rcx, rbx
    lea     rdx, api_cf
    mov     r8d, 11                 ; "CreateFileA"
    call    FindExport
    mov     r12, rax

    mov     rcx, [rsp+58h]
    lea     rdx, api_wf
    mov     r8d, 9                  ; "WriteFile"
    call    FindExport
    mov     r13, rax

    mov     rcx, [rsp+58h]
    lea     rdx, api_ch
    mov     r8d, 11                 ; "CloseHandle"
    call    FindExport
    mov     r14, rax

    mov     rcx, [rsp+58h]
    lea     rdx, api_gp
    mov     r8d, 18                 ; "GetCurrentProcessId"
    call    FindExport
    mov     r15, rax

    test    r12, r12
    jz      give_up
    test    r13, r13
    jz      give_up
    test    r14, r14
    jz      give_up

    ; ---- build buffer "PICOK:" + pid(4) + CRLF  at rsp+40h ----
    lea     rsi, content
    lea     rdi, [rsp+40h]
    mov     ecx, 6
    rep movsb

    test    r15, r15
    jz      no_pid
    call    r15                     ; GetCurrentProcessId
    mov     [rdi], eax
    add     rdi, 4
no_pid:
    mov     word ptr [rdi], 0A0Dh
    add     rdi, 2

    ; ---- CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, NORMAL, 0) ----
    lea     rcx, out_path
    mov     edx, 40000000h
    mov     r8d, 1
    xor     r9d, r9d
    mov     qword ptr [rsp+20h], 2          ; CREATE_ALWAYS
    mov     qword ptr [rsp+28h], 80h        ; FILE_ATTRIBUTE_NORMAL
    mov     qword ptr [rsp+30h], 0
    call    r12
    mov     rbx, rax
    cmp     rax, -1
    je      give_up

    ; ---- WriteFile(h, buf, len, &written, 0) ----
    mov     rcx, rbx
    lea     rdx, [rsp+40h]
    mov     r8,  rdi
    sub     r8,  rdx                        ; length
    lea     r9,  [rsp+38h]
    mov     qword ptr [rsp+20h], 0
    call    r13

    mov     rcx, rbx
    call    r14                             ; CloseHandle

give_up:
    xor     eax, eax
    add     rsp, 60h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
PicEntry ENDP

; FindExport(rcx = module base, rdx = name bytes, r8d = name length) -> rax = function VA or 0
FindExport PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 40h

    mov     r12, rcx                        ; base
    mov     r13, rdx                        ; wanted name
    mov     r14d, r8d

    mov     eax, [r12+3Ch]
    test    eax, eax
    jz      fe_fail
    lea     r15, [r12+rax]                  ; nt headers
    mov     eax, [r15+88h]                  ; export dir RVA
    test    eax, eax
    jz      fe_fail
    lea     rbx, [r12+rax]                  ; export dir VA

    mov     r15d, [rbx+18h]                 ; NumberOfNames
    mov     esi, [rbx+20h]                  ; AddressOfNames RVA
    add     rsi, r12
    mov     edi, [rbx+24h]                  ; AddressOfNameOrdinals RVA
    add     rdi, r12
    mov     r11d, [rbx+1Ch]                 ; AddressOfFunctions RVA
    add     r11, r12
    mov     [rsp+38h], r11

    xor     r10d, r10d
fe_loop:
    cmp     r10d, r15d
    jae     fe_fail
    mov     eax, [rsi+r10*4]
    lea     r8, [r12+rax]                   ; candidate name
    mov     ecx, r14d
    mov     r9, r13
fe_cmp:
    test    ecx, ecx
    jz      fe_hit
    mov     al, [r8]
    cmp     al, [r9]
    jne     fe_next
    inc     r8
    inc     r9
    dec     ecx
    jmp     fe_cmp
fe_hit:
    movzx   eax, word ptr [rdi+r10*2]        ; ordinal
    mov     r11, [rsp+38h]
    mov     eax, [r11+rax*4]                ; function RVA
    test    eax, eax
    jz      fe_fail
    lea     rax, [r12+rax]
    jmp     fe_done
fe_next:
    inc     r10d
    jmp     fe_loop
fe_fail:
    xor     eax, eax
fe_done:
    add     rsp, 40h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
FindExport ENDP

; ---- data kept inside .text so the blob stays one section ----
ALIGN 8
name_k32    dw 'k','e','r','n','e','l','3','2','.','d','l','l'
api_cf      db 'CreateFileA'
api_wf      db 'WriteFile'
api_ch      db 'CloseHandle'
api_gp      db 'GetCurrentProcessId'
content     db 'PICOK:'
out_path    db 'C:\Users\Public\pic-ok.txt',0

_TEXT ENDS
END
