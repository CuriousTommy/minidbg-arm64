#ifndef MINIDBG_REGISTERS_HPP
#define MINIDBG_REGISTERS_HPP

#include <elf.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/uio.h>

#include <algorithm>
#include <array>
#include <string>
#include <cstdint>

namespace minidbg {
#if __i386__ || __x86_64__
    enum class reg {
        rax, rbx, rcx, rdx,
        rdi, rsi, rbp, rsp,
        r8,  r9,  r10, r11,
        r12, r13, r14, r15,
        rip, rflags,    cs,
        orig_rax, fs_base,
        gs_base,
        fs, gs, ss, ds, es
    };
#elif __aarch64__
    enum class reg {
        // Parameter/result registers
        r0, r1, r2, r3, r4, r5, r6, r7,
        // Indirect result location register
        r8,
        // Temporary registers
        r9, r10, r11, r12, r13, r14, r15,
        // The first intra-procedure-call scratch register (can be used by
        // call veneers and PLT code); at other times may be used as a
        // temporary register.
        r16,
        // The second intra-procedure-call temporary register (can be used by 
        // call veneers and PLT code); at other times may be used as a 
        // temporary register.                                         
        r17,
        // The Platform Register, if needed; otherwise a temporary register. 
        // See notes.
        r18,
        // Callee-saved registers
        r19, r20, r21, r22, r23, r24, r25, r26, r27, r28,
        // The Frame Pointer
        r29,
        // The Link Register.
        r30,
        // The Stack Pointer.
        sp,
        // Program Counter
        pc,
        // Processor State (Not A Register)
        pstate,
    };
#endif

    static constexpr std::size_t n_registers = 34;

    struct reg_descriptor {
        reg r;
        int dwarf_r;
        std::string name;
    };

    //have a look in /usr/include/sys/user.h for how to lay this out
    #if __i386__ || __x86_64__
    static const std::array<reg_descriptor, n_registers> g_register_descriptors {{
            { reg::r15, 15, "r15" },
            { reg::r14, 14, "r14" },
            { reg::r13, 13, "r13" },
            { reg::r12, 12, "r12" },
            { reg::rbp, 6, "rbp" },
            { reg::rbx, 3, "rbx" },
            { reg::r11, 11, "r11" },
            { reg::r10, 10, "r10" },
            { reg::r9, 9, "r9" },
            { reg::r8, 8, "r8" },
            { reg::rax, 0, "rax" },
            { reg::rcx, 2, "rcx" },
            { reg::rdx, 1, "rdx" },
            { reg::rsi, 4, "rsi" },
            { reg::rdi, 5, "rdi" },
            { reg::orig_rax, -1, "orig_rax" },
            { reg::rip, -1, "rip" },
            { reg::cs, 51, "cs" },
            { reg::rflags, 49, "eflags" },
            { reg::rsp, 7, "rsp" },
            { reg::ss, 52, "ss" },
            { reg::fs_base, 58, "fs_base" },
            { reg::gs_base, 59, "gs_base" },
            { reg::ds, 53, "ds" },
            { reg::es, 50, "es" },
            { reg::fs, 54, "fs" },
            { reg::gs, 55, "gs" },
    }};
    #elif __aarch64__
    // TODO: figure out what the dwarf values should be...
    static const std::array<reg_descriptor, n_registers> g_register_descriptors {{
            { reg::r0, 0, "r0" },
            { reg::r1, 1, "r1" },
            { reg::r2, 2, "r2" },
            { reg::r3, 3, "r3" },
            { reg::r4, 4, "r4" },
            { reg::r5, 5, "r5" },
            { reg::r6, 6, "r6" },
            { reg::r7, 7, "r7" },
            { reg::r8, 8, "r8" },
            { reg::r9, 9, "r9" },
            { reg::r10, 10, "r10" },
            { reg::r11, 11, "r11" },
            { reg::r12, 12, "r12" },
            { reg::r13, 13, "r13" },
            { reg::r14, 14, "r14" },
            { reg::r15, 15, "r15" },
            { reg::r16, 16, "r16" },
            { reg::r17, 17, "r17" },
            { reg::r18, 18, "r18" },
            { reg::r19, 19, "r19" },
            { reg::r20, 20, "r20" },
            { reg::r21, 21, "r21" },
            { reg::r22, 22, "r22" },
            { reg::r23, 23, "r23" },
            { reg::r24, 24, "r24" },
            { reg::r25, 25, "r25" },
            { reg::r26, 26, "r26" },
            { reg::r27, 27, "r27" },
            { reg::r28, 28, "r28" },
            { reg::r29, 29, "r29" },
            { reg::r30, 30, "r30" },
            { reg::sp, 29, "sp" },
            { reg::pc, 30, "pc" },
            { reg::pstate, 30, "pstate" },
    }};
    #endif

    uint64_t get_register_value(pid_t pid, reg r) {
        user_regs_struct regs;
        struct iovec reg_iov = {
            .iov_base = &regs,
            .iov_len = sizeof(reg)
        };
        ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &reg_iov);
        auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                               [r](auto&& rd) { return rd.r == r; });

        return *(reinterpret_cast<uint64_t*>(&regs) + (it - begin(g_register_descriptors)));
    }

    void set_register_value(pid_t pid, reg r, uint64_t value) {
        user_regs_struct regs;
        struct iovec reg_iov = {
            .iov_base = &regs,
            .iov_len = sizeof(reg)
        };

        ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &reg_iov);
        auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                               [r](auto&& rd) { return rd.r == r; });

        *(reinterpret_cast<uint64_t*>(&regs) + (it - begin(g_register_descriptors))) = value;
        ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &reg_iov);
    }

    uint64_t get_register_value_from_dwarf_register (pid_t pid, unsigned regnum) {
        auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                               [regnum](auto&& rd) { return rd.dwarf_r == regnum; });
        if (it == end(g_register_descriptors)) {
            throw std::out_of_range{"Unknown dwarf register"};
        }

        return get_register_value(pid, it->r);
    }

    std::string get_register_name(reg r) {
        auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                               [r](auto&& rd) { return rd.r == r; });
        return it->name;
    }

    reg get_register_from_name(const std::string& name) {
        auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                               [name](auto&& rd) { return rd.name == name; });
        return it->r;
    }
}

#endif
