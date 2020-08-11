/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh & Dang Hoang Vu, 2015 */

/* Sample code to demonstrate how to emulate X86 code */

#include <capstone/platform.h>
#include <capstone/capstone.h>

#include <unicorn/unicorn.h>
// #include "unicorn_test.h"
#include <string.h>
#include <Windows.h>


// code to be emulated
#define X86_CODE32 "\x41\x4a\x66\x0f\xef\xc1" // INC ecx; DEC edx; PXOR xmm0, xmm1
#define X86_CODE32_JUMP "\xeb\x02\x90\x90\x90\x90\x90\x90" // jmp 4; nop; nop; nop; nop; nop; nop
// #define X86_CODE32_SELF "\xeb\x1c\x5a\x89\xd6\x8b\x02\x66\x3d\xca\x7d\x75\x06\x66\x05\x03\x03\x89\x02\xfe\xc2\x3d\x41\x41\x41\x41\x75\xe9\xff\xe6\xe8\xdf\xff\xff\xff\x31\xd2\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xca\x7d\x41\x41\x41\x41"
//#define X86_CODE32 "\x51\x51\x51\x51" // PUSH ecx;
#define X86_CODE32_LOOP "\x41\x4a\xeb\xfe" // INC ecx; DEC edx; JMP self-loop
#define X86_CODE32_MEM_WRITE "\x89\x0D\xAA\xAA\xAA\xAA\x41\x4a" // mov [0xaaaaaaaa], ecx; INC ecx; DEC edx
#define X86_CODE32_MEM_READ "\x8B\x0D\xAA\xAA\xAA\xAA\x41\x4a" // mov ecx,[0xaaaaaaaa]; INC ecx; DEC edx

#define X86_CODE32_JMP_INVALID "\xe9\xe9\xee\xee\xee\x41\x4a" //  JMP outside; INC ecx; DEC edx
#define X86_CODE32_INOUT "\x41\xE4\x3F\x4a\xE6\x46\x43" // INC ecx; IN AL, 0x3f; DEC edx; OUT 0x46, AL; INC ebx
#define X86_CODE32_INC "\x40"   // INC eax

//#define X86_CODE64 "\x41\xBC\x3B\xB0\x28\x2A \x49\x0F\xC9 \x90 \x4D\x0F\xAD\xCF\x49\x87\xFD\x90\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9" // <== still crash
//#define X86_CODE64 "\x41\xBC\x3B\xB0\x28\x2A\x49\x0F\xC9\x90\x4D\x0F\xAD\xCF\x49\x87\xFD\x90\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9"
#define X86_CODE64 "\x41\xBC\x3B\xB0\x28\x2A\x49\x0F\xC9\x90\x4D\x0F\xAD\xCF\x49\x87\xFD\x90\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9\x4D\x29\xF4\x49\x81\xC9\xF6\x8A\xC6\x53\x4D\x87\xED\x48\x0F\xAD\xD2\x49\xF7\xD4\x48\xF7\xE1\x4D\x19\xC5\x4D\x89\xC5\x48\xF7\xD6\x41\xB8\x4F\x8D\x6B\x59\x4D\x87\xD0\x68\x6A\x1E\x09\x3C\x59"
#define X86_CODE16 "\x00\x00"   // add   byte ptr [bx + si], al
#define X86_CODE64_SYSCALL "\x0f\x05" // SYSCALL

// memory address where emulation starts
#define ADDRESS 0x1000000

// callback for tracing basic blocks
static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

// callback for tracing instruction
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    int eflags;
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);

    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
    printf(">>> --- EFLAGS is 0x%x\n", eflags);

    // Uncomment below code to stop the emulation using uc_emu_stop()
    // if (address == 0x1000009)
    //    uc_emu_stop(uc);
}

// callback for tracing instruction
static void hook_code64(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint64_t rip;

    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
    printf(">>> RIP is 0x%"PRIx64 "\n", rip);

    // Uncomment below code to stop the emulation using uc_emu_stop()
    // if (address == 0x1000009)
    //    uc_emu_stop(uc);
}

// callback for tracing memory access (READ or WRITE)
static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
    switch(type) {
        default:
            // return false to indicate we want to stop emulation
            return false;
        case UC_MEM_WRITE_UNMAPPED:
                 printf(">>> Missing memory is being WRITE at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n",
                         address, size, value);
                 // map this memory in with 2MB in size
                 uc_mem_map(uc, 0xaaaa0000, 2 * 1024*1024, UC_PROT_ALL);
                 // return true to indicate we want to continue
                 return true;
    }
}

static void hook_mem64(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
    switch(type) {
        default: break;
        case UC_MEM_READ:
                 printf(">>> Memory is being READ at 0x%"PRIx64 ", data size = %u\n",
                         address, size);
                 break;
        case UC_MEM_WRITE:
                 printf(">>> Memory is being WRITE at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n",
                         address, size, value);
                 break;
    }
}

// callback for IN instruction (X86).
// this returns the data read from the port
static uint32_t hook_in(uc_engine *uc, uint32_t port, int size, void *user_data)
{
    uint32_t eip;

    uc_reg_read(uc, UC_X86_REG_EIP, &eip);

    printf("--- reading from port 0x%x, size: %u, address: 0x%x\n", port, size, eip);

    switch(size) {
        default:
            return 0;   // should never reach this
        case 1:
            // read 1 byte to AL
            return 0xf1;
        case 2:
            // read 2 byte to AX
            return 0xf2;
            break;
        case 4:
            // read 4 byte to EAX
            return 0xf4;
    }
}

// callback for OUT instruction (X86).
static void hook_out(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data)
{
    uint32_t tmp = 0;
    uint32_t eip;

    uc_reg_read(uc, UC_X86_REG_EIP, &eip);

    printf("--- writing to port 0x%x, size: %u, value: 0x%x, address: 0x%x\n", port, size, value, eip);

    // confirm that value is indeed the value of AL/AX/EAX
    switch(size) {
        default:
            return;   // should never reach this
        case 1:
            uc_reg_read(uc, UC_X86_REG_AL, &tmp);
            break;
        case 2:
            uc_reg_read(uc, UC_X86_REG_AX, &tmp);
            break;
        case 4:
            uc_reg_read(uc, UC_X86_REG_EAX, &tmp);
            break;
    }

    printf("--- register value = 0x%x\n", tmp);
}

// callback for SYSCALL instruction (X86).
static void hook_syscall(uc_engine *uc, void *user_data)
{
    uint64_t rax;

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    if (rax == 0x100) {
        rax = 0x200;
        uc_reg_write(uc, UC_X86_REG_RAX, &rax);
    } else
        printf("ERROR: was not expecting rax=0x%"PRIx64 " in syscall\n", rax);
}

static void test_i386(void)
{
    uc_engine *uc;
    uc_err err;
    uint32_t tmp;
    uc_hook trace1, trace2;

    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register
    // XMM0 and XMM1 registers, low qword then high qword
    uint64_t r_xmm0[2] = {0x08090a0b0c0d0e0f, 0x0001020304050607};
    uint64_t r_xmm1[2] = {0x8090a0b0c0d0e0f0, 0x0010203040506070};

    printf("Emulate i386 code\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);
    uc_reg_write(uc, UC_X86_REG_XMM0, &r_xmm0);
    uc_reg_write(uc, UC_X86_REG_XMM1, &r_xmm1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction by having @begin > @end
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    uc_reg_read(uc, UC_X86_REG_XMM0, &r_xmm0);
    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);
    printf(">>> XMM0 = 0x%.16"PRIx64"%.16"PRIx64"\n", r_xmm0[1], r_xmm0[0]);

    // read from memory
    if (!uc_mem_read(uc, ADDRESS, &tmp, sizeof(tmp)))
        printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", ADDRESS, tmp);
    else
        printf(">>> Failed to read 4 bytes from [0x%x]\n", ADDRESS);

    uc_close(uc);
}

static void test_i386_map_ptr(void)
{
    uc_engine *uc;
    uc_err err;
    uint32_t tmp;
    uc_hook trace1, trace2;
    void *mem;

    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register

    printf("===================================\n");
    printf("Emulate i386 code - use uc_mem_map_ptr()\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // malloc 2MB memory for this emulation
    mem = calloc(1, 2 * 1024 * 1024);
    if (mem == NULL) {
        printf("Failed to malloc()\n");
        return;
    }

    uc_mem_map_ptr(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL, mem);

    // write machine code to be emulated to memory
    if (!memcpy(mem, X86_CODE32, sizeof(X86_CODE32) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction by having @begin > @end
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);

    // read from memory
    if (!uc_mem_read(uc, ADDRESS, &tmp, sizeof(tmp)))
        printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", ADDRESS, tmp);
    else
        printf(">>> Failed to read 4 bytes from [0x%x]\n", ADDRESS);

    uc_close(uc);
    free(mem);
}

static void test_i386_jump(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    printf("===================================\n");
    printf("Emulate i386 code with jump\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_JUMP,
          sizeof(X86_CODE32_JUMP) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // tracing 1 basic block with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, ADDRESS, ADDRESS);

    // tracing 1 instruction at ADDRESS
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_JUMP) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    printf(">>> Emulation done. Below is the CPU context\n");

    uc_close(uc);
}

// emulate code that loop forever
static void test_i386_loop(void)
{
    uc_engine *uc;
    uc_err err;

    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register

    printf("===================================\n");
    printf("Emulate i386 code that loop forever\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_LOOP, sizeof(X86_CODE32_LOOP) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

    // emulate machine code in 2 seconds, so we can quit even
    // if the code loops
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_LOOP) - 1, 2 * UC_SECOND_SCALE, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);

    uc_close(uc);
}

// emulate code that read invalid memory
static void test_i386_invalid_mem_read(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register

    printf("===================================\n");
    printf("Emulate i386 code that read from invalid memory\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_MEM_READ, sizeof(X86_CODE32_MEM_READ) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction by having @begin > @end
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_MEM_READ) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);

    uc_close(uc);
}

// emulate code that write invalid memory
static void test_i386_invalid_mem_write(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2, trace3;
    uint32_t tmp;

    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register

    printf("===================================\n");
    printf("Emulate i386 code that write to invalid memory\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_MEM_WRITE, sizeof(X86_CODE32_MEM_WRITE) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction by having @begin > @end
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // intercept invalid memory events
    uc_hook_add(uc, &trace3, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid, NULL, 1, 0);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_MEM_WRITE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);

    // read from memory
    if (!uc_mem_read(uc, 0xaaaaaaaa, &tmp, sizeof(tmp)))
        printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", 0xaaaaaaaa, tmp);
    else
        printf(">>> Failed to read 4 bytes from [0x%x]\n", 0xaaaaaaaa);

    if (!uc_mem_read(uc, 0xffffffaa, &tmp, sizeof(tmp)))
        printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", 0xffffffaa, tmp);
    else
        printf(">>> Failed to read 4 bytes from [0x%x]\n", 0xffffffaa);

    uc_close(uc);
}

// emulate code that jump to invalid memory
static void test_i386_jump_invalid(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register

    printf("===================================\n");
    printf("Emulate i386 code that jumps to invalid memory\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_JMP_INVALID, sizeof(X86_CODE32_JMP_INVALID) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instructions by having @begin > @end
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_JMP_INVALID) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);

    uc_close(uc);
}

static void test_i386_inout(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2, trace3, trace4;


    int r_eax = 0x1234;     // EAX register
    int r_ecx = 0x6789;     // ECX register

    printf("===================================\n");
    printf("Emulate i386 code with IN/OUT instructions\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_INOUT, sizeof(X86_CODE32_INOUT) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_EAX, &r_eax);
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instructions
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // uc IN instruction
    uc_hook_add(uc, &trace3, UC_HOOK_INSN, hook_in, NULL, 1, 0, UC_X86_INS_IN);
    // uc OUT instruction
    uc_hook_add(uc, &trace4, UC_HOOK_INSN, hook_out, NULL, 1, 0, UC_X86_INS_OUT);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_INOUT) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    printf(">>> EAX = 0x%x\n", r_eax);
    printf(">>> ECX = 0x%x\n", r_ecx);

    uc_close(uc);
}

// emulate code and save/restore the CPU context
static void test_i386_context_save(void)
{
    uc_engine *uc;
    uc_context *context;
    uc_err err;

    int r_eax = 0x1;    // EAX register

    printf("===================================\n");
    printf("Save/restore CPU context in opaque blob\n");

    // initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 8KB memory for this emulation
    uc_mem_map(uc, ADDRESS, 8 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_INC, sizeof(X86_CODE32_INC) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_EAX, &r_eax);

    // emulate machine code in infinite time
    printf(">>> Running emulation for the first time\n");

    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_INC) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    printf(">>> EAX = 0x%x\n", r_eax);

    // allocate and save the CPU context
    printf(">>> Saving CPU context\n");

    err = uc_context_alloc(uc, &context);
    if (err) {
        printf("Failed on uc_context_alloc() with error returned: %u\n", err);
        return;
    }

    err = uc_context_save(uc, context);
    if (err) {
        printf("Failed on uc_context_save() with error returned: %u\n", err);
        return;
    }

    // emulate machine code again
    printf(">>> Running emulation for the second time\n");

    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_INC) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    printf(">>> EAX = 0x%x\n", r_eax);

    // restore CPU context
    err = uc_context_restore(uc, context);
    if (err) {
        printf("Failed on uc_context_restore() with error returned: %u\n", err);
        return;
    }

    // now print out some registers
    printf(">>> CPU context restored. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    printf(">>> EAX = 0x%x\n", r_eax);

    // free the CPU context
    err = uc_free(context);
    if (err) {
        printf("Failed on uc_free() with error returned: %u\n", err);
        return;
    }

    uc_close(uc);
}

#if 0
static void test_i386_invalid_c6c7(void)
{
    uc_engine *uc;
    uc_err err;
    uint8_t codebuf[16] = { 0 };
    uint8_t opcodes[] = { 0xc6, 0xc7 };
    bool valid_masks[4][8] = {
        { true, false, false, false, false, false, false, false },
        { true, false, false, false, false, false, false, false },
        { true, false, false, false, false, false, false, false },
        { true, false, false, false, false, false, false, true  },
    };
    int i, j, k;

    printf("===================================\n");
    printf("Emulate i386 C6/C7 opcodes\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    for (i = 0; i < 2; ++i) {
        // set opcode
        codebuf[0] = opcodes[i];

        for (j = 0; j < 4; ++j) {
            for (k = 0; k < 8; ++k) {
                // set Mod bits
                codebuf[1]  = (uint8_t) (j << 6);
                // set Reg bits
                codebuf[1] |= (uint8_t) (k << 3);

                // perform validation
                if (uc_mem_write(uc, ADDRESS, codebuf, sizeof(codebuf))) {
                    printf("Failed to write emulation code to memory, quit!\n");
                    return;
                }
                err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(codebuf), 0, 0);
                if ((err != UC_ERR_INSN_INVALID) ^ valid_masks[j][k]) {
                    printf("Unexpected uc_emu_start() error returned %u: %s\n",
                           err, uc_strerror(err));
                    return;
                }
            }
        }
    }

    printf(">>> Emulation done.\n");

    uc_close(uc);
}
#endif

static void test_x86_64(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2, trace3, trace4;

    int64_t rax = 0x71f3029efd49d41d;
    int64_t rbx = 0xd87b45277f133ddb;
    int64_t rcx = 0xab40d1ffd8afc461;
    int64_t rdx = 0x919317b4a733f01;
    int64_t rsi = 0x4c24e753a17ea358;
    int64_t rdi = 0xe509a57d2571ce96;
    int64_t r8 = 0xea5b108cc2b9ab1f;
    int64_t r9 = 0x19ec097c8eb618c1;
    int64_t r10 = 0xec45774f00c5f682;
    int64_t r11 = 0xe17e9dbec8c074aa;
    int64_t r12 = 0x80f86a8dc0f6d457;
    int64_t r13 = 0x48288ca5671c5492;
    int64_t r14 = 0x595f72f6e4017f6e;
    int64_t r15 = 0x1efd97aea331cccc;

    int64_t rsp = ADDRESS + 0x200000;


    printf("Emulate x86_64 code\n");

    // Initialize emulator in X86-64bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE64, sizeof(X86_CODE64) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);

    uc_reg_write(uc, UC_X86_REG_RAX, &rax);
    uc_reg_write(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_write(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_write(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_write(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_write(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_write(uc, UC_X86_REG_R8, &r8);
    uc_reg_write(uc, UC_X86_REG_R9, &r9);
    uc_reg_write(uc, UC_X86_REG_R10, &r10);
    uc_reg_write(uc, UC_X86_REG_R11, &r11);
    uc_reg_write(uc, UC_X86_REG_R12, &r12);
    uc_reg_write(uc, UC_X86_REG_R13, &r13);
    uc_reg_write(uc, UC_X86_REG_R14, &r14);
    uc_reg_write(uc, UC_X86_REG_R15, &r15);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instructions in the range [ADDRESS, ADDRESS+20]
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code64, NULL, ADDRESS, ADDRESS+20);

    // tracing all memory WRITE access (with @begin > @end)
    uc_hook_add(uc, &trace3, UC_HOOK_MEM_WRITE, hook_mem64, NULL, 1, 0);

    // tracing all memory READ access (with @begin > @end)
    uc_hook_add(uc, &trace4, UC_HOOK_MEM_READ, hook_mem64, NULL, 1, 0);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE64) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_read(uc, UC_X86_REG_R8, &r8);
    uc_reg_read(uc, UC_X86_REG_R9, &r9);
    uc_reg_read(uc, UC_X86_REG_R10, &r10);
    uc_reg_read(uc, UC_X86_REG_R11, &r11);
    uc_reg_read(uc, UC_X86_REG_R12, &r12);
    uc_reg_read(uc, UC_X86_REG_R13, &r13);
    uc_reg_read(uc, UC_X86_REG_R14, &r14);
    uc_reg_read(uc, UC_X86_REG_R15, &r15);

    printf(">>> RAX = 0x%" PRIx64 "\n", rax);
    printf(">>> RBX = 0x%" PRIx64 "\n", rbx);
    printf(">>> RCX = 0x%" PRIx64 "\n", rcx);
    printf(">>> RDX = 0x%" PRIx64 "\n", rdx);
    printf(">>> RSI = 0x%" PRIx64 "\n", rsi);
    printf(">>> RDI = 0x%" PRIx64 "\n", rdi);
    printf(">>> R8 = 0x%" PRIx64 "\n", r8);
    printf(">>> R9 = 0x%" PRIx64 "\n", r9);
    printf(">>> R10 = 0x%" PRIx64 "\n", r10);
    printf(">>> R11 = 0x%" PRIx64 "\n", r11);
    printf(">>> R12 = 0x%" PRIx64 "\n", r12);
    printf(">>> R13 = 0x%" PRIx64 "\n", r13);
    printf(">>> R14 = 0x%" PRIx64 "\n", r14);
    printf(">>> R15 = 0x%" PRIx64 "\n", r15);

    uc_close(uc);
}

static void test_x86_64_syscall(void)
{
    uc_engine *uc;
    uc_hook trace1;
    uc_err err;

    int64_t rax = 0x100;

    printf("===================================\n");
    printf("Emulate x86_64 code with 'syscall' instruction\n");

    // Initialize emulator in X86-64bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE64_SYSCALL, sizeof(X86_CODE64_SYSCALL) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // hook interrupts for syscall
    uc_hook_add(uc, &trace1, UC_HOOK_INSN, hook_syscall, NULL, 1, 0, UC_X86_INS_SYSCALL);

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_RAX, &rax);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE64_SYSCALL) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);

    printf(">>> RAX = 0x%" PRIx64 "\n", rax);

    uc_close(uc);
}

static void test_x86_16(void)
{
    uc_engine *uc;
    uc_err err;
    uint8_t tmp;

    int32_t eax = 7;
    int32_t ebx = 5;
    int32_t esi = 6;

    printf("Emulate x86 16-bit code\n");

    // Initialize emulator in X86-16bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_16, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 8KB memory for this emulation
    uc_mem_map(uc, 0, 8 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, 0, X86_CODE16, sizeof(X86_CODE16) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_EBX, &ebx);
    uc_reg_write(uc, UC_X86_REG_ESI, &esi);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, 0, sizeof(X86_CODE16) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    // read from memory
    if (!uc_mem_read(uc, 11, &tmp, 1))
        printf(">>> Read 1 bytes from [0x%x] = 0x%x\n", 11, tmp);
    else
        printf(">>> Failed to read 1 bytes from [0x%x]\n", 11);

    uc_close(uc);
}

#if 0
int main(int argc, char** argv, char** envp)
{




	if (argc == 2) {
		if (!strcmp(argv[1], "-16")) {
			test_x86_16();
		}
		else if (!strcmp(argv[1], "-32")) {
			test_i386();
			test_i386_map_ptr();
			test_i386_inout();
			test_i386_context_save();
			test_i386_jump();
			test_i386_loop();
			test_i386_invalid_mem_read();
			test_i386_invalid_mem_write();
			test_i386_jump_invalid();
			//test_i386_invalid_c6c7();
		}
		else if (!strcmp(argv[1], "-64")) {
			test_x86_64();
			test_x86_64_syscall();
		}
		else if (!strcmp(argv[1], "-h")) {
			printf("Syntax: %s <-16|-32|-64>\n", argv[0]);
		}
	}
	else {
		test_x86_16();
		test_i386();
		test_i386_map_ptr();
		test_i386_inout();
		test_i386_context_save();
		test_i386_jump();
		test_i386_loop();
		test_i386_invalid_mem_read();
		test_i386_invalid_mem_write();
		test_i386_jump_invalid();
		//test_i386_invalid_c6c7();
		test_x86_64();
		test_x86_64_syscall();

	}

	return 0;
}
#endif



//0193DE53     8B00                 MOV EAX, DWORD PTR DS : [EAX]
//0193DE55     05 00100000          ADD EAX, 1000
//0193DE5A     0305 FFFFFFFF        ADD EAX, DWORD PTR DS : [FFFFFFFF]

#define TEST_HOOK_CODE "\x8B\x00\x05\x00\x10\x00\x00\xE8\x01\x01\x02\x02\x03\x05\xFF\xFF\xFF\xFF"
#define TEST_HOOK_CODE_SIZE     sizeof(TEST_HOOK_CODE)
#define REG						uint32_t
#define NAKED					__declspec(naked)
#define address_t               uint32_t
#define GetJumpOffset(src, dest, cmdsize)   ((src)-(dest)-(cmdsize))
static csh handle;
static uint8_t* g_hook_code[1024];
static uint8_t* g_hook_code_size = 1024;
#define HOOKINFO_ID					10
//hook code...
//PUSH ID
//JUMP HANDLE STUB

//handle stub...
//PUSH ID
//JUMP 

#pragma pack(push)
#pragma pack(1)
//0073DE53 > $ E9 18B2D100    JMP sample_a.01459070
//0073DE58     68 AAAAAAAA    PUSH AAAAAAAA
typedef struct {
    uint8_t cmd;    //0xE9
    address_t offset;
    //uint8_t cmd;    //0x68
    //address_t id;
} FixContent;
#pragma pack(pop)

#define MIN_HOOK_FIX_SIZE               5
#define STUB_SIZE                       0x20
#define SPRING_BOARD_SIZE               0x20

typedef struct {
    REG eax;
    REG ebx;
    REG ecx;
    REG edx;
    REG esi;
    REG edi;
    REG esp;
    REG ebp;
    REG efl;
}X86RegInfo;

void agent(void* fn, X86RegInfo* before, X86RegInfo* after) {
    //该函数不能有参数，必须从内存中把参数些为立即数
    __asm {
        pushad
        mov eax, before.efl

        mov eax, before.eax
        mov ebx, before.ebx
        mov ecx, before.ecx
        mov edx, before.edx
        mov esi, before.esi
        mov edi, before.edi
        mov esp, before.esp
        mov ebp, before.ebp
        call fn
        mov after.eax, eax
        mov after.ebx, ebx
        mov after.ecx, ecx
        mov after.edx, edx
        mov after.esi, esi
        mov after.edi, edi
        mov after.esp, esp
        mov after.ebp, ebp
        popad
    }
}

//019EDE53     A1 78563412    MOV EAX, DWORD PTR DS : [12345678]
//019EDE58     8B1D 78563412  MOV EBX, DWORD PTR DS : [12345678]
//019EDE5E     8B0D 78563412  MOV ECX, DWORD PTR DS : [12345678]
//019EDE64     8B15 78563412  MOV EDX, DWORD PTR DS : [12345678]
//019EDE6A     8B35 78563412  MOV ESI, DWORD PTR DS : [12345678]
//019EDE70     8B3D 78563412  MOV EDI, DWORD PTR DS : [12345678]
//019EDE76     8B25 78563412  MOV ESP, DWORD PTR DS : [12345678]
//019EDE7C     8B2D 78563412  MOV EBP, DWORD PTR DS : [12345678]
//019EDE82     E8 F1779510    CALL 12345678
//019EDE87     A3 78563412    MOV DWORD PTR DS : [12345678] , EAX
//019EDE8C     891D 78563412  MOV DWORD PTR DS : [12345678] , EBX
//019EDE92     890D 78563412  MOV DWORD PTR DS : [12345678] , ECX
//019EDE98     8915 78563412  MOV DWORD PTR DS : [12345678] , EDX
//019EDE9E     8935 78563412  MOV DWORD PTR DS : [12345678] , ESI
//019EDEA4     893D 78563412  MOV DWORD PTR DS : [12345678] , EDI
//019EDEAA     8925 78563412  MOV DWORD PTR DS : [12345678] , ESP
//019EDEB0     892D 78563412  MOV DWORD PTR DS : [12345678] , EBP

#pragma pack(push)
#pragma pack(1)
typedef struct {
    uint8_t cmd;
    uint8_t *address;
}MovContentAndEax;
typedef struct {
    uint8_t cmd[2];
    uint8_t *address;
}MovContentAndOtherReg;
//019EDEB7     50             PUSH EAX
//019EDEB8     9C             PUSHFD
//019EDEB9     58             POP EAX
//019EDEBA     A3 78563412    MOV DWORD PTR DS : [12345678] , EAX
//019EDEBF     58             POP EAX
typedef struct {
    uint8_t cmd1[4];
    uint8_t* address;
    uint8_t cmd2;
}MovEFlagsToContent;
//019EDEC1     50             PUSH EAX
//019EDEC2     A1 78563412    MOV EAX, DWORD PTR DS : [12345678]
//019EDEC7     50             PUSH EAX
//019EDEC8     9D             POPFD
//019EDEC9     58             POP EAX
typedef struct {
    uint8_t cmd1[2];
    uint8_t* address;
    uint8_t cmd2[3];
}MovContentToEFlags;
typedef struct {                 //mov reg, [addr]  //mov [addr], reg
    MovContentAndEax eax;        //0xA1             //0xA3
    MovContentAndOtherReg ebx;   //0x8B1D           //0x891D
    MovContentAndOtherReg ecx;   //0x8B0D           //0x890D
    MovContentAndOtherReg edx;   //0x8B15           //0x8915
    MovContentAndOtherReg esi;   //0x8B35           //0x8935
    MovContentAndOtherReg edi;   //0x8B3D           //0x893D
    MovContentAndOtherReg esp;   //0x8B25           //0x8925
    MovContentAndOtherReg ebp;   //0x8B2D           //0x892D
} MovContentAndRegs;
typedef struct {
    uint8_t cmd;
    uint8_t* address;
}CallAddress;
//019EDED0     83C4 04        ADD ESP,4
//019EDED3     FF6424 FC      JMP DWORD PTR SS : [ESP - 4]
typedef struct {
    uint8_t cmd[7];
}RetAddress;
typedef struct {
    MovEFlagsToContent bakupCurrentEFlags;
    MovContentAndRegs bakupCurrentContext;
    MovContentToEFlags setupVMEFlags;
    MovContentAndRegs setupVMContext;
    CallAddress call;
    MovEFlagsToContent bakupVMEFlags;
    MovContentAndRegs bakupVMContext;
    MovContentAndRegs setupCurrentContext;
    MovContentToEFlags setupCurrentEFlags;
    uint8_t retcmd;
}InvokeAgent;
typedef struct {
    MovContentToEFlags setupVMEFlags;
    MovContentAndRegs setupVMContext;
    uint8_t lastcmd[0x20];
    RetAddress ret;
}RetAgent;
#pragma pack(pop)

void initBackupEFlags(MovEFlagsToContent *cmdBuffer) {
    //019EDEB7     50             PUSH EAX
    //019EDEB8     9C             PUSHFD
    //019EDEB9     58             POP EAX
    //019EDEBA     A3 78563412    MOV DWORD PTR DS : [12345678] , EAX
    //019EDEBF     58             POP EAX
    *(uint32_t*)cmdBuffer->cmd1 = 0xA3589C50;
    cmdBuffer->cmd2 = 0x58;
}

void initSetupEFlags(MovContentToEFlags* cmdBuffer) {
    //019EDEC1     50             PUSH EAX
    //019EDEC2     A1 78563412    MOV EAX, DWORD PTR DS : [12345678]
    //019EDEC7     50             PUSH EAX
    //019EDEC8     9D             POPFD
    //019EDEC9     58             POP EAX
    *(uint16_t*)cmdBuffer->cmd1 = 0xA150;
    cmdBuffer->cmd2[0] = 0x50;
    cmdBuffer->cmd2[1] = 0x9D;
    cmdBuffer->cmd2[2] = 0x58;
}

void initRegsBackupCmd(MovContentAndRegs *cmdBuffer) {
    cmdBuffer->eax.cmd = 0xA3;
    *(uint16_t*)cmdBuffer->ebx.cmd = 0x1D89;
    *(uint16_t*)cmdBuffer->ecx.cmd = 0x0D89;
    *(uint16_t*)cmdBuffer->edx.cmd = 0x1589;
    *(uint16_t*)cmdBuffer->esi.cmd = 0x3589;
    *(uint16_t*)cmdBuffer->edi.cmd = 0x3D89;
    *(uint16_t*)cmdBuffer->esp.cmd = 0x2589;
    *(uint16_t*)cmdBuffer->ebp.cmd = 0x2D89;
}

void initRegsSetupCmd(MovContentAndRegs* cmdBuffer) {
    cmdBuffer->eax.cmd = 0xA1;
    *(uint16_t*)cmdBuffer->ebx.cmd = 0x1D8B;
    *(uint16_t*)cmdBuffer->ecx.cmd = 0x0D8B;
    *(uint16_t*)cmdBuffer->edx.cmd = 0x158B;
    *(uint16_t*)cmdBuffer->esi.cmd = 0x358B;
    *(uint16_t*)cmdBuffer->edi.cmd = 0x3D8B;
    *(uint16_t*)cmdBuffer->esp.cmd = 0x258B;
    *(uint16_t*)cmdBuffer->ebp.cmd = 0x2D8B;
}

void initCallCmd(CallAddress* call) {
    call->cmd = 0xE8;
}

void initRetCmd(RetAddress* ret) {
    uint8_t cmd[] = { 0x83, 0xC4, 0x04, 0xFF, 0x64, 0x24, 0xFC };
    memcpy(ret->cmd, cmd, sizeof(cmd));
}

void setBackupEFlagsCmdParam(MovEFlagsToContent* cmdBuffer, X86RegInfo* param) {
    cmdBuffer->address = &param->efl;
}

void setSetupEFlagsCmdParam(MovContentToEFlags* cmdBuffer, X86RegInfo* param) {
    cmdBuffer->address = &param->efl;
}

void setRegCmdParam(MovContentAndRegs* cmdBuffer, X86RegInfo* param) {
    cmdBuffer->eax.address = &param->eax;
    cmdBuffer->ebx.address = &param->ebx;
    cmdBuffer->ecx.address = &param->ecx;
    cmdBuffer->edx.address = &param->edx;
    cmdBuffer->esi.address = &param->esi;
    cmdBuffer->edi.address = &param->edi;
    cmdBuffer->esp.address = &param->esp;
    cmdBuffer->ebp.address = &param->ebp;
}

void setCallCmdParam(CallAddress* call, void *address) {
    call->address = (uint32_t)address - (uint32_t)call - 5;
}

void initCallAgent(InvokeAgent* agent) {
    uint32_t oldp;
    VirtualProtect(agent, sizeof(InvokeAgent), PAGE_EXECUTE_READWRITE, &oldp);
    memset(agent, 0x90, sizeof(InvokeAgent));
    initBackupEFlags(&agent->bakupCurrentEFlags);
    initRegsBackupCmd(&agent->bakupCurrentContext);
    initSetupEFlags(&agent->setupVMEFlags);
    initRegsSetupCmd(&agent->setupVMContext);
    initCallCmd(&agent->call);
    initBackupEFlags(&agent->bakupVMEFlags);
    initRegsBackupCmd(&agent->bakupVMContext);
    initRegsSetupCmd(&agent->setupCurrentContext);
    initSetupEFlags(&agent->setupCurrentEFlags);
    agent->retcmd = 0xC3;
}
void resetCallAgent(InvokeAgent*agent, void* fn, X86RegInfo* vminfo, X86RegInfo* realinfo) {
    setBackupEFlagsCmdParam(&agent->bakupCurrentEFlags, realinfo);
    setRegCmdParam(&agent->bakupCurrentContext, realinfo);
    setSetupEFlagsCmdParam(&agent->setupVMEFlags, vminfo);
    setRegCmdParam(&agent->setupVMContext, vminfo);
    setCallCmdParam(&agent->call, fn);
    setBackupEFlagsCmdParam(&agent->bakupVMEFlags, vminfo);
    setRegCmdParam(&agent->bakupVMContext, vminfo);
    setRegCmdParam(&agent->setupCurrentContext, realinfo);
    setSetupEFlagsCmdParam(&agent->setupCurrentEFlags, realinfo);
}
void initRetAgent(RetAgent* agent) {
    uint32_t oldp;
    VirtualProtect(agent, sizeof(RetAgent), PAGE_EXECUTE_READWRITE, &oldp);
    memset(agent, 0x90, sizeof(RetAgent));
    initSetupEFlags(&agent->setupVMEFlags);
    initRegsSetupCmd(&agent->setupVMContext);
    initRetCmd(&agent->ret);
}
void resetRetAgent(RetAgent* agent, X86RegInfo* vminfo, uint8_t *cmd, size_t cmdsize) {
    setSetupEFlagsCmdParam(&agent->setupVMEFlags, vminfo);
    memcpy(agent->lastcmd, cmd, cmdsize);
    setRegCmdParam(&agent->setupVMContext, vminfo);
}

typedef struct {
    uint32_t id;
    uint8_t stub[STUB_SIZE];
    uint8_t springboard[SPRING_BOARD_SIZE];
	uint8_t enterVM[SPRING_BOARD_SIZE];
    InvokeAgent invokeAgent;
    RetAgent invokeRetAgent;
    FixContent fix;
    size_t fixSize;
    uint8_t* fn;
	uint32_t fnrange;
    uint8_t* fake;
	X86RegInfo regs;
} HookInfo;

HookInfo g_HookInfo[100] = {0};

uint8_t *getDebugFunctionAddress(uint8_t* fn) {
	return *((uint32_t*)(fn + 1)) + fn + 5;
}

bool initCS() {
    cs_err err = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);

    if (err)
        return false;

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    return true;
}

int disasm(uint8_t* code, size_t size, uint64_t address, cs_insn** insn) {
    return cs_disasm(handle, code, size, address, 0, insn);
}


void printRegs(uc_engine* uc) {
    uint32_t eax, ebx, ecx, edx, esi, edi, esp, ebp;
    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &edx);
    uc_reg_read(uc, UC_X86_REG_ESI, &esi);
    uc_reg_read(uc, UC_X86_REG_EDI, &edi);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uc_reg_read(uc, UC_X86_REG_EBP, &ebp);

    printf("eax:0x%08x ebx:0x%08x ecx:0x%08x edx:0x%08x esi:0x%08x edi:0x%08x esp:0x%08x ebp:0x%08x \n",
        eax, ebx, ecx, edx, esi, edi, esp, ebp);
}

bool genStub(uint8_t *stub, size_t stubSizeOfByte, uint8_t *address, cs_insn* insn, size_t insnNum) {
    uint8_t* p = address;
    uint8_t* p1 = stub;
	uint32_t oldp;
	VirtualProtect(stub, stubSizeOfByte, PAGE_EXECUTE_READWRITE, &oldp);
    for (int i = 0; i < insnNum; ++i) {

        if (*p >= 0xE0 && *p <= 0xE9 || *p >= 0x70 && *p <= 0x79) {
            return false;
        }

        memcpy(p1, p, insn[i].size);
        p += insn[i].size;
        p1 += insn[i].size;
    }

    return true;
}

void genSpringBoard(uint8_t* base, uint32_t id, uint8_t* address) {

	uint32_t oldp;
	VirtualProtect(address, SPRING_BOARD_SIZE, PAGE_EXECUTE_READWRITE, &oldp);
    int pos = 0;
    base[pos] = 0x68; pos++;
    *(uint32_t*)&base[pos] = id; pos += 4;
    base[pos] = 0xE9; pos++;
    *(uint32_t*)&base[pos] = address - (uint8_t*)& base[pos] - 4; pos += 4;
    uint32_t size = 0;
    VirtualProtect(base, pos, PAGE_EXECUTE_READWRITE, &size);
}


//void NAKED enterVM() {
//	__asm {
//		push ebp
//		push esp
//		push edi
//		push esi
//		push edx
//		push ecx
//		push ebx
//		push eax
//		call saveContext
//		jmp address		//Tail address of the protected chunk 
//	}
//}

void genEnterVM(uint8_t* base, uint8_t* saveContextFn, uint8_t* protectedChunkTailAddress) {

	uint32_t oldp;
	VirtualProtect(base, SPRING_BOARD_SIZE, PAGE_EXECUTE_READWRITE, &oldp);

	int pos = 0;
	base[pos] = 0x55; pos++;
	base[pos] = 0x54; pos++;
	base[pos] = 0x57; pos++;
	base[pos] = 0x56; pos++;
	base[pos] = 0x52; pos++;
	base[pos] = 0x51; pos++;
	base[pos] = 0x53; pos++;
	base[pos] = 0x50; pos++;
	base[pos] = 0xE8; pos++;
	*(uint32_t*)& base[pos] = saveContextFn - &base[pos] - 4; pos += 4;
	base[pos] = 0xE9; pos++;
	*(uint32_t*)& base[pos] = protectedChunkTailAddress - &base[pos] - 4; pos += 4;
	base[pos] = 0x90; pos++;

}


size_t copyCode(uint8_t* begin, uint8_t* buffer, size_t size) {
    uint8_t* src = begin;
    uint8_t* dest = buffer;
	int pos = 0;

	cs_insn* insn;
	size_t count;
	count = disasm(begin, 1024, begin, &insn);
	for (int i = 0; i < count; ++i) {
		if (insn[i].bytes[0] == 0xCC) {
			break;
		}
		memcpy(&dest[pos], insn[i].bytes, insn[i].size);
		pos += insn[i].size;
	}

    return pos;
}


static int hook_code2(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);




bool mem_read_operation_invalid2(uc_engine* uc, uc_mem_type type,
	uint64_t address, int size, int64_t value, void* user_data)
{
	int r_eax;     // EAX register
	int r_ip;

	switch (type) {
	case UC_MEM_READING:
	{
		void* returnData = (void*)value;
		memcpy(returnData, address, size);
		return true;
	}break;
	case UC_MEM_WRITING:
	{
		memcpy(address, &value, size);
		return true;
	}break;


	}
	return false;
}

void startVM(HookInfo* hookInfo, uint8_t* code, size_t length)
{
	uc_engine* uc;
	uc_err err;
	uint32_t tmp;
	uc_hook trace1, trace2;

	err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
	if (err) {
		printf("Failed on open() with error returned: %u\n", err);
		return;
	}
	uint32_t mask = -1;
	mask = mask ^ 0xFFF;
	uint32_t membase = (uint32_t)hookInfo->fn & mask;
	uc_mem_map(uc, membase, 2 * 1024 * 1024, UC_PROT_ALL);
	if (uc_mem_write(uc, hookInfo->fn, code, length)) {
		printf("Failed to write code to memory, quit!\n");
		return;
	}
	uint8_t instr_bytes[0x100] = { 0 };
	if (uc_mem_read(uc, hookInfo->fn, instr_bytes, length)) {
		printf("Failed to write code to memory, quit!\n");
		return;
	}
	
	uc_reg_write(uc, UC_X86_REG_EAX, &hookInfo->regs.eax);
	uc_reg_write(uc, UC_X86_REG_EBX, &hookInfo->regs.ebx);
	uc_reg_write(uc, UC_X86_REG_ECX, &hookInfo->regs.ecx);
	uc_reg_write(uc, UC_X86_REG_EDX, &hookInfo->regs.edx);
	uc_reg_write(uc, UC_X86_REG_ESI, &hookInfo->regs.esi);
	uc_reg_write(uc, UC_X86_REG_EDI, &hookInfo->regs.edi);
	uc_reg_write(uc, UC_X86_REG_ESP, &hookInfo->regs.esp);
	uc_reg_write(uc, UC_X86_REG_EBP, &hookInfo->regs.ebp);

	printf("register{\n"
		"eax:0x%08x \n"
		"ebx:0x%08x \n"
		"ecx:0x%08x \n"
		"edx:0x%08x \n"
		"esi:0x%08x \n"
		"edi:0x%08x \n"
		"esp:0x%08x \n"
		"ebp:0x%08x \n"
		"}\n", hookInfo->regs.eax, hookInfo->regs.ebx, hookInfo->regs.ecx, hookInfo->regs.edx, hookInfo->regs.esi, hookInfo->regs.edi, hookInfo->regs.esp, hookInfo->regs.ebp);



	//uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED |
	//	UC_HOOK_MEM_READ_PROT | UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT |
	//	UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH | UC_HOOK_MEM_READING
	//	, mem_read_operation_invalid, NULL, 1, 0);

	uc_hook_add(uc, &trace1, UC_HOOK_MEM_READING_AND_WRITING
		, mem_read_operation_invalid2, NULL, 1, 0);

	uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code2, NULL, 1, 0);

	err = uc_emu_start(uc, hookInfo->fn, hookInfo->fn + length - 1, 0, 0);
	if (err) {
		printf("Failed on uc_emu_start() with error returned %u: %s\n",
			err, uc_strerror(err));
	}

	uc_close(uc);
}

void __stdcall saveContext(REG eax, REG ebx, REG ecx, REG edx, REG esi, REG edi, REG esp, REG ebp, uint32_t id) {
	HookInfo* hi = &g_HookInfo[id];
	hi->regs.eax = eax;
	hi->regs.ebx = ebx;
	hi->regs.ecx = ecx;
	hi->regs.edx = edx;
	hi->regs.esi = esi;
	hi->regs.edi = edi;
	hi->regs.esp = esp+8;
	hi->regs.ebp = ebp;
	
	startVM(hi, g_hook_code, hi->fnrange);
}

bool makeHook(uint8_t *fn, size_t protectedRange, void *fakefn, HookInfo *hookinfo,size_t codeChunksize) {
    hookinfo->fn = fn;
    hookinfo->fake = fakefn;
    hookinfo->id = HOOKINFO_ID;
	hookinfo->fnrange = codeChunksize;
    cs_insn* insn;
    size_t count = disasm(fn, 0x20, fn, &insn);
    size_t fixSize = 0;
	int i = 0;
    for (; i < count; ++i) {
        fixSize += insn[i].size;
        if (fixSize >= MIN_HOOK_FIX_SIZE) {
			i++;
            break;
        }
    }

    if (fixSize >= MIN_HOOK_FIX_SIZE) {
        genStub(hookinfo->stub, STUB_SIZE, fn, insn, i);
        genSpringBoard(hookinfo->springboard, hookinfo->id, hookinfo->enterVM);
		genEnterVM(hookinfo->enterVM, getDebugFunctionAddress(saveContext), (uint32_t)fn+protectedRange);
        initCallAgent(&hookinfo->invokeAgent);
        initRetAgent(&hookinfo->invokeRetAgent);
    }
    
	//install hook
	uint32_t oldp;
	VirtualProtect(fn, codeChunksize, PAGE_EXECUTE_READWRITE, &oldp);
	memset(fn, 0x90, codeChunksize);
	int pos = 0;
	fn[pos] = 0xE9; pos++;
	*(uint32_t*)& fn[pos] = (uint32_t)hookinfo->springboard - (uint32_t)& fn[pos] - 4;
	VirtualProtect(fn, codeChunksize, oldp, &oldp);

	

    cs_free(insn, count);
}



//8个通用寄存器：EAX、EBX、ECX、EDX、ESI、EDI、ESP、EBP
//
//1个标志寄存器：EFLAGS
//
//6个段寄存器：CS、DS、ES、FS、GS、SS
//
//5个控制寄存器：CR0、CR1、CR2、CR3、CR4
//
//8个调试寄存器：DR0、DR1、DR2、DR3、DR4、DR5、DR6、DR7
//
//4个系统地址寄存器：GDTR、IDTR、LDTR、TR


int foo(int a, int b) {
	return a + b;
}

void example(int *ret, int a, int b) {
	*ret = foo(a, b);
}



void testHook();
void initHook() {
    memset(g_hook_code, 0x0, g_hook_code_size);
	//uint32_t offset = (*((uint32_t*)(((uint8_t*)example) + 1)));
	//void* fn = offset + (uint32_t)example + 5;
	uint8_t* fn = getDebugFunctionAddress(example);
	//void* fn = example;
    size_t protectedSize = copyCode(fn, g_hook_code, g_hook_code_size);
	HookInfo* hi = &g_HookInfo[HOOKINFO_ID];
	makeHook(fn, protectedSize, 0, hi, protectedSize);
    uint8_t* func_entry = fn;
}

bool inRange(uint32_t val, uint32_t begin, uint32_t end) {
	return val >= begin && val <= end;
}
// callback for tracing instruction
static int hook_code2(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	static uint32_t oldeip = 0;
	static cs_insn oldinsn = {0};
	static 
	HookInfo* hi = &g_HookInfo[HOOKINFO_ID];
    uint8_t instr_bytes[100] = { 0 };
    uc_mem_read(uc, address, instr_bytes, 0x20);
	cs_insn* insn = NULL;
    size_t count = 0;
    bool ret = false;

    //test print
    printRegs(uc);

	if (size) {
		count = disasm(instr_bytes, 0x20, address, &insn);
		printf("0x%" PRIx64 ":\t%s\t%s\n", insn[0].address, insn[0].mnemonic, insn[0].op_str);
	}
	else {
		printf("0x% jump exception", address);
	}
    if (insn) {
        if (insn[1].bytes[0] == 0xC3) {
            X86RegInfo vm;
            memset(&vm, 0x0, sizeof(X86RegInfo));
            uc_reg_read(uc, UC_X86_REG_EAX, &vm.eax);
            uc_reg_read(uc, UC_X86_REG_EBX, &vm.ebx);
            uc_reg_read(uc, UC_X86_REG_ECX, &vm.ecx);
            uc_reg_read(uc, UC_X86_REG_EDX, &vm.edx);
            uc_reg_read(uc, UC_X86_REG_ESI, &vm.esi);
            uc_reg_read(uc, UC_X86_REG_EDI, &vm.edi);
            uc_reg_read(uc, UC_X86_REG_ESP, &vm.esp);
            uc_reg_read(uc, UC_X86_REG_EBP, &vm.ebp);
            uc_reg_read(uc, UC_X86_REG_EFLAGS, &vm.efl);
            resetRetAgent(&hi->invokeRetAgent, &vm, insn[0].bytes, insn[0].size);
            ((void(*)()) &hi->invokeRetAgent)();//该函数不返回
        }
        else if (insn->bytes[0] == 0xE8) {
            uint32_t eip, esp, efl;
            uc_reg_read(uc, UC_X86_REG_EIP, &eip);
            uc_reg_read(uc, UC_X86_REG_ESP, &esp);
            uc_reg_read(uc, UC_X86_REG_EFLAGS, &efl);
            uint8_t* target = *(uint32_t*)&insn->bytes[1] + eip + 5;

            if (!inRange(target, hi->fn, hi->fn + hi->fnrange)) {
                X86RegInfo vm, rm;
                memset(&vm, 0x0, sizeof(X86RegInfo));
                memset(&rm, 0x0, sizeof(X86RegInfo));
                uc_reg_read(uc, UC_X86_REG_EAX, &vm.eax);
                uc_reg_read(uc, UC_X86_REG_EBX, &vm.ebx);
                uc_reg_read(uc, UC_X86_REG_ECX, &vm.ecx);
                uc_reg_read(uc, UC_X86_REG_EDX, &vm.edx);
                uc_reg_read(uc, UC_X86_REG_ESI, &vm.esi);
                uc_reg_read(uc, UC_X86_REG_EDI, &vm.edi);
                uc_reg_read(uc, UC_X86_REG_ESP, &vm.esp);
                uc_reg_read(uc, UC_X86_REG_EBP, &vm.ebp);
                uc_reg_read(uc, UC_X86_REG_EFLAGS, &vm.efl);

                //agent(address, &vm, &rm);

                resetCallAgent(&hi->invokeAgent, target, &vm, &rm);
                ((void(*)()) & hi->invokeAgent)();

                uc_reg_write(uc, UC_X86_REG_EIP, &eip);
                uc_reg_write(uc, UC_X86_REG_EAX, &vm.eax);
                uc_reg_write(uc, UC_X86_REG_EBX, &vm.ebx);
                uc_reg_write(uc, UC_X86_REG_ECX, &vm.ecx);
                uc_reg_write(uc, UC_X86_REG_EDX, &vm.edx);
                uc_reg_write(uc, UC_X86_REG_ESI, &vm.esi);
                uc_reg_write(uc, UC_X86_REG_EDI, &vm.edi);
                uc_reg_write(uc, UC_X86_REG_ESP, &vm.esp);
                uc_reg_write(uc, UC_X86_REG_EBP, &vm.ebp);
                uc_reg_write(uc, UC_X86_REG_EFLAGS, &vm.efl);

                eip += 5;
                uc_reg_write(uc, UC_X86_REG_EIP, &eip);
                ret = true;
                goto Exit;
            }
        }
    }
	uc_reg_read(uc, UC_X86_REG_EIP, &oldeip);

Exit:
	if (insn) {
		oldinsn = insn[0];
		cs_free(insn, count);
	}

	return ret;
}

bool mem_read_operation_invalid(uc_engine* uc, uc_mem_type type,
	uint64_t address, int size, int64_t value, void* user_data)
{
	int r_eax;     // EAX register
	int r_ip ;
    uc_reg_read(uc, UC_X86_REG_EIP, &r_ip);
    if (address == 0xffffffff || address == 0xffffffffffffffff) {
        uc_emu_stop(uc);
        return false;
    }
    //if (r_ip >= ADDRESS + TEST_HOOK_CODE_SIZE) {
    //    uc_emu_stop(uc);
    //    return false;
    //}
	switch (type) {
	    case UC_MEM_READ:               // Memory is read from
	    {
            printf("UC_MEM_READ HOOK\r\n");
	    }break;
	    case UC_MEM_WRITE:              // Memory is written to
	    {
            printf("UC_MEM_WRITE HOOK\r\n");
	    }break;
	    case UC_MEM_FETCH:              // Memory is fetched
	    {
            printf("UC_MEM_FETCH HOOK\r\n");
	    }break;
	    case UC_MEM_READ_UNMAPPED:      // Unmapped memory is read from
	    {
            printf("UC_MEM_READ_UNMAPPED HOOK\r\n");
            return true;
	    }break;
	    case UC_MEM_WRITE_UNMAPPED:     // Unmapped memory is written to
	    {
            printf("UC_MEM_WRITE_UNMAPPED HOOK\r\n");
            return true;
	    }break;
	    case UC_MEM_FETCH_UNMAPPED:     // Unmapped memory is fetched
	    {
            printf("UC_MEM_FETCH_UNMAPPED HOOK\r\n");
            return true;
	    }break;
	    case UC_MEM_WRITE_PROT:         // Write to write protected: but mapped: memory
	    {
            printf("UC_MEM_WRITE_PROT HOOK\r\n");
            return true;
	    }break;
	    case UC_MEM_READ_PROT:          // Read from read protected: but mapped: memory
	    {
            printf("UC_MEM_READ_PROT HOOK\r\n");
            return true;
	    }break;
	    case UC_MEM_FETCH_PROT:         // Fetch from non-executable: but mapped: memory
	    {
            printf("UC_MEM_FETCH_PROT HOOK\r\n");
            return true;
	    }break;
        case UC_MEM_READING:
        {
            void* returnData = (void*)value;
            memcpy(returnData, address, size);
            printf("UC_MEM_READING HOOK\r\n");
            return true;
        }break;
		case UC_MEM_WRITING:
		{
			void* returnData = (void*)value;
			memcpy(returnData, address, size);
			printf("UC_MEM_READING HOOK\r\n");
			return true;
		}break;


	}

    //if (type == UC_MEM_READ_UNMAPPED)
    //{
    //	uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    //	uc_reg_read(uc, UC_X86_REG_EIP, &r_ip);
    //	return true;
    //}
	return false;
}

#define BUFF_ADDRESS        0x2000000

char* testReadDest = "\x06\x03\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

void test() {

}

static void test_i386hook(void)
{
	uc_engine* uc;
	uc_err err;
	uint32_t tmp;
	uc_hook trace1, trace2;

    if (!initCS()) {
        printf("Failed on initCS() with error returned: %u\n", 0);
        return;
    }

	//int r_eax = BUFF_ADDRESS;     // EAX register
    int r_eax = (int)testReadDest;     // EAX register

	err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
	if (err) {
		printf("Failed on open() with error returned: %u\n", err);
		return;
	}

	uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);
	if (uc_mem_write(uc, ADDRESS, TEST_HOOK_CODE, sizeof(TEST_HOOK_CODE) - 1)) {
		printf("Failed to write code to memory, quit!\n");
		return;
	}

    char* szbuff = "\x04\x03\x02\x01";
    uc_mem_map(uc, BUFF_ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);
    if (uc_mem_write(uc, BUFF_ADDRESS, szbuff, 4)) {
        printf("Failed to write code to memory, quit!\n");
        return;
    }
    //qemu_get_ram_ptr()

	uc_reg_write(uc, UC_X86_REG_EAX, &r_eax);

	uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED |
        UC_HOOK_MEM_READ_PROT | UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT |
        UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH | UC_HOOK_MEM_READING_AND_WRITING
        , mem_read_operation_invalid, NULL, 1, 0);

	uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

	uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code2, NULL, 1, 0);

	err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
	if (err) {
		printf("Failed on uc_emu_start() with error returned %u: %s\n",
			err, uc_strerror(err));
	}

	uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);

	uc_close(uc);
}
















void testHook() {
	int a = 10;
	int b = 33;
	int c = 0;

	example(&c, a, b);
}



int main(int argc, char** argv, char** envp)
{

	if (!initCS()) {
		printf("Failed on initCS() with error returned: %u\n", 0);
		return;
	}

    //int a = myAdd(10, 20);

	initHook();//初始化虚拟机保护
	testHook();//测试函数


	return 0;
}