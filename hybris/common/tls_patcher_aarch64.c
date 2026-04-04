/*
 * Copyright (c) 2025 Nikita Ukhrenkov <thekit@disroot.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>

/* AArch64 instruction opcodes and system register encodings */
#define MRS_OPCODE 0xD53
#define TPIDR_EL0  0x5E82

/* Thunk size in bytes (4 instructions = 16 bytes) */
#define THUNK_SIZE 16

/* Instruction format for MRS X<rt>, TPIDR_EL0 */
struct __attribute__((__packed__)) mrs_inst {
    uint32_t rt:5;        /* 0:4   - Destination register */
    uint32_t sys_reg:15;  /* 5:19  - System register encoding */
    uint32_t opcode:12;   /* 20:31 - Must be 0xD53 (MRS instruction) */
};
_Static_assert(sizeof(struct mrs_inst) == 4, "MRS instruction size must be 4");

static int is_mrs_tpidr_el0(uint32_t instruction) {
    const struct mrs_inst* mrs = (const struct mrs_inst*)&instruction;
    return mrs->opcode == MRS_OPCODE && mrs->sys_reg == TPIDR_EL0;
}

/* Count MRS TPIDR_EL0 instructions in a code segment */
static size_t hybris_count_tls_arch(void* segment_addr, size_t segment_size) {
    uint32_t* text = (uint32_t*)segment_addr;
    size_t count = segment_size / sizeof(uint32_t);
    size_t mrs_count = 0;

    for (size_t i = 0; i < count; i++) {
        if (is_mrs_tpidr_el0(text[i]))
            mrs_count++;
    }
    return mrs_count;
}

/* Generate a thunk that adjusts the thread pointer and jumps back.
 *
 * Thunk code (4 instructions, 16 bytes):
 *   mrs x<rt>, tpidr_el0      ; Read glibc thread pointer
 *   add x<rt>, x<rt>, #offset ; Adjust to hybris TLS area
 *   b <return_addr>           ; Branch back to instruction after original MRS
 *   nop                       ; Padding
 */
static void generate_tls_thunk(int tls_offset_words, uint32_t target_register,
                               void* mrs_location, void* thunk) {
    uint32_t* code = (uint32_t*)thunk;
    int tls_offset_bytes = tls_offset_words * 8;

    if (tls_offset_bytes < 0 || tls_offset_bytes > 0xFFF) {
        fprintf(stderr, "HYBRIS: fatal: TLS offset %d bytes out of ADD immediate range [0, 4095]\n",
                tls_offset_bytes);
        abort();
    }

    /* Calculate branch offset back to the instruction after the original MRS */
    void* return_addr = (char*)mrs_location + 4;
    intptr_t return_diff = (intptr_t)return_addr - (intptr_t)((char*)thunk + 8);
    if (return_diff % 4 != 0 || return_diff / 4 < -(1 << 25) || return_diff / 4 >= (1 << 25)) {
        fprintf(stderr, "HYBRIS: fatal: return branch from thunk %p to %p out of range\n",
                thunk, return_addr);
        abort();
    }
    int32_t return_offset = return_diff / 4;

    /* MRS X<rt>, TPIDR_EL0 */
    code[0] = 0xD53BD040 | target_register;

    /* ADD X<rt>, X<rt>, #imm12 */
    code[1] = 0x91000000 | (target_register << 5) | target_register | (tls_offset_bytes << 10);

    /* B <return_offset> */
    code[2] = 0x14000000 | (return_offset & 0x3FFFFFF);

    /* NOP */
    code[3] = 0xD503201F;
}

/* Replace MRS instruction with branch to thunk */
static void patch_mrs_with_branch(uint32_t* mrs_location, void* thunk) {
    intptr_t diff = (intptr_t)thunk - (intptr_t)mrs_location;
    if (diff % 4 != 0 || diff / 4 < -(1 << 25) || diff / 4 >= (1 << 25)) {
        fprintf(stderr, "HYBRIS: fatal: branch from MRS at %p to thunk %p out of range\n",
                (void*)mrs_location, thunk);
        abort();
    }
    int32_t word_offset = diff / 4;

    /* B <offset> : opcode 0b000101 in bits [31:26] */
    *mrs_location = 0x14000000 | (word_offset & 0x3FFFFFF);
}

static void hybris_patch_tls_arch(void* segment_addr, size_t segment_size, int tls_offset) {
    uint32_t* text = (uint32_t*)segment_addr;
    size_t count = segment_size / sizeof(uint32_t);
    int patches_applied = 0;

    for (size_t i = 0; i < count; i++) {
        if (!is_mrs_tpidr_el0(text[i]))
            continue;

        const struct mrs_inst* mrs = (const struct mrs_inst*)&text[i];

        /* Allocate 16 bytes from the thunk region */
        void* thunk = hybris_allocate_thunk_near(&text[i], THUNK_SIZE);

        /* Generate thunk and patch the instruction */
        generate_tls_thunk(tls_offset, mrs->rt, &text[i], thunk);
        patch_mrs_with_branch(&text[i], thunk);
        patches_applied++;
    }

    if (patches_applied > 0) {
        __builtin___clear_cache(segment_addr, (char*)segment_addr + segment_size);
    }
}
