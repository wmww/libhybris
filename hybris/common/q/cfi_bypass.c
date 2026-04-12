/*
 * Patch bionic's __cfi_slowpath to a no-op return.
 *
 * Android C/C++ libraries use Control Flow Integrity (CFI) as a security
 * feature. Indirect calls go through __cfi_slowpath in libdl.so, which looks
 * up the target address in a sparse shadow table (built by the bionic
 * dynamic linker at process start, covering only system libraries).
 *
 * When libhybris loads vendor libraries from a glibc process (where the
 * bionic linker is NOT the process linker), those libraries' code ranges
 * are never registered in the shadow. Indirect calls from vendor code then
 * crash inside __cfi_slowpath when it dereferences uninitialized shadow
 * entries.
 *
 * libhybris contains a CFIShadowWriter implementation in linker_cfi.cpp,
 * but it's only activated by linker_main() (the Halium-style "libhybris is
 * the process linker" deployment). In our deployment (glibc chroot on stock
 * Android), the entry point is android_linker_init(), which never wires
 * shadow setup up. Even if it did, vendor libraries lack __cfi_check
 * symbols, so a properly initialized shadow would mark them
 * kUncheckedShadow and pass everything anyway. Patching __cfi_slowpath to
 * `ret` is semantically equivalent.
 *
 * Implementation: scan /proc/self/maps for a mapping of libdl.so, walk its
 * in-memory ELF headers to find the dynamic symbol table, and look up
 * __cfi_slowpath by name. Overwrite its first instruction with `ret`
 * (0xd65f03c0). The symbol is guaranteed to be dynamically exported on any
 * Android with CFI — Clang emits direct calls to it from every
 * CFI-instrumented binary, so the OS itself couldn't boot without it.
 */

#include "cfi_bypass.h"

#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__aarch64__)

/* Count entries in a DT_GNU_HASH table. The total symbol count is one past
 * the largest symbol index reachable from any bucket's chain — find the
 * highest bucket start, then walk that chain to its terminator bit. */
static uint32_t nsyms_from_gnu_hash(const uint32_t *gh)
{
    uint32_t nbuckets = gh[0];
    uint32_t symoffset = gh[1];
    uint32_t bloom_size = gh[2];
    /* Header = 4 uint32s, then bloom filter of bloom_size uint64s = bloom_size*2 uint32s. */
    const uint32_t *buckets = gh + 4 + bloom_size * 2;
    const uint32_t *chain = buckets + nbuckets;

    uint32_t max_start = 0;
    for (uint32_t i = 0; i < nbuckets; i++) {
        if (buckets[i] > max_start) max_start = buckets[i];
    }
    /* All buckets empty — the only symbols are the un-hashed prefix. */
    if (max_start < symoffset) return symoffset;

    uint32_t idx = max_start;
    /* Each chain entry's LSB marks end-of-bucket; the last bucket's last
     * entry is the last symbol in the table. Bound the walk to catch a
     * corrupt chain with no terminator. */
    for (uint32_t step = 0; step < 1000000; step++) {
        if (chain[idx - symoffset] & 1) return idx + 1;
        idx++;
    }
    return 0;
}

/* Find __cfi_slowpath in a mapped libdl.so by walking its dynamic symbol
 * table. Returns the instruction address to patch, or NULL on failure. */
static uint32_t *find_cfi_slowpath(unsigned long load_base)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)load_base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return NULL;
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) return NULL;

    /* Locate PT_DYNAMIC. */
    const Elf64_Phdr *ph = (const Elf64_Phdr *)(load_base + eh->e_phoff);
    const Elf64_Dyn *dyn = NULL;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn = (const Elf64_Dyn *)(load_base + ph[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return NULL;

    /* Walk dynamic entries for the symbol/string tables and a hash table to
     * bound the symtab walk. bionic's linker relocates DT_* d_ptr values to
     * absolute addresses when the segment is loaded; if a value happens to
     * be below load_base, treat it as a load-relative offset instead. */
    const Elf64_Sym *symtab = NULL;
    const char *strtab = NULL;
    const uint32_t *gnu_hash = NULL;
    const uint32_t *sysv_hash = NULL;
    for (; dyn->d_tag != DT_NULL; dyn++) {
        uintptr_t val = (uintptr_t)dyn->d_un.d_ptr;
        if (val && val < load_base) val += load_base;
        switch (dyn->d_tag) {
            case DT_SYMTAB:   symtab    = (const Elf64_Sym *)val; break;
            case DT_STRTAB:   strtab    = (const char *)val; break;
            case DT_GNU_HASH: gnu_hash  = (const uint32_t *)val; break;
            case DT_HASH:     sysv_hash = (const uint32_t *)val; break;
            default: break;
        }
    }
    if (!symtab || !strtab) return NULL;

    /* Determine exact symbol count. Prefer GNU hash (only hash on modern
     * bionic); fall back to classic SysV hash's nchain if present. */
    uint32_t nsyms = 0;
    if (gnu_hash)       nsyms = nsyms_from_gnu_hash(gnu_hash);
    else if (sysv_hash) nsyms = sysv_hash[1]; /* nchain == nsym */
    if (nsyms == 0) return NULL;

    for (uint32_t i = 0; i < nsyms; i++) {
        if (symtab[i].st_name == 0) continue; /* unnamed (STN_UNDEF at 0) */
        if (strcmp(strtab + symtab[i].st_name, "__cfi_slowpath") != 0) continue;
        if (symtab[i].st_value == 0) return NULL; /* imported, not defined here */
        return (uint32_t *)(load_base + symtab[i].st_value);
    }
    return NULL;
}

/* Patch a single aarch64 instruction to `ret` (0xd65f03c0). Uses RW → write
 * → RX to avoid ever requesting PROT_EXEC|PROT_WRITE simultaneously, which
 * some SELinux policies and kernel configs deny. */
static int patch_instruction_to_ret(uint32_t *insn)
{
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    uintptr_t page_mask = (uintptr_t)page_size - 1;
    uintptr_t start = (uintptr_t)insn & ~page_mask;
    /* An aarch64 instruction is 4 bytes and always naturally aligned, so it
     * cannot straddle a page boundary. One page is always enough. */
    size_t len = page_size;

    if (mprotect((void *)start, len, PROT_READ | PROT_WRITE) != 0) {
        return -1;
    }
    *insn = 0xd65f03c0; /* ret */
    __builtin___clear_cache((char *)insn, (char *)insn + 4);
    /* Restoring PROT_EXEC is important: the patched instruction only runs if
     * the page is executable. A failure here is rare (would require a
     * policy that allowed the initial RW transition but denies adding X
     * back) but leaves the page unexecutable, so a later CFI-checked call
     * would SIGSEGV on instruction fetch. Warn so the cause is discoverable. */
    if (mprotect((void *)start, len, PROT_READ | PROT_EXEC) != 0) {
        fprintf(stderr, "libhybris: WARNING failed to restore PROT_EXEC on libdl.so page "
                        "after CFI patch; future indirect calls may fault\n");
        return -1;
    }
    return 0;
}

void hybris_patch_bionic_cfi(void)
{
    /* Idempotent: once we successfully patch (or definitively fail), do
     * nothing on subsequent calls. The first call from android_linker_init()
     * typically finds no libdl.so mapping yet (it only gets pulled in by the
     * first vendor library's DT_NEEDED), so we leave patched=0 and let later
     * calls retry. */
    static int patched = 0;
    if (patched) return;

    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return;

    char line[512];
    unsigned long libdl_base = 0;
    char libdl_path[256] = {0};
    while (fgets(line, sizeof(line), f)) {
        unsigned long lo, hi;
        char perms[5];
        char path[256] = {0};
        int n = sscanf(line, "%lx-%lx %4s %*s %*s %*s %255s", &lo, &hi, perms, path);
        if (n < 3) continue;
        /* Match a path ending in "/libdl.so" (avoids matching "/libdl.so.2"
         * and similar). */
        size_t plen = strlen(path);
        const char suffix[] = "/libdl.so";
        size_t slen = sizeof(suffix) - 1;
        if (plen < slen || strcmp(path + plen - slen, suffix) != 0) continue;
        /* First mapping of libdl.so is its load base (lowest-address LOAD
         * segment, typically r--p containing the ELF header). */
        if (libdl_base == 0 || lo < libdl_base) {
            libdl_base = lo;
            strncpy(libdl_path, path, sizeof(libdl_path) - 1);
        }
    }
    fclose(f);

    if (libdl_base == 0) {
        /* libdl.so not mapped yet — will retry on a later call. */
        return;
    }

    uint32_t *insn = find_cfi_slowpath(libdl_base);
    if (!insn) {
        /* Symbol not found or ELF parsing failed. No reason to retry. */
        patched = 1;
        fprintf(stderr, "libhybris: WARNING failed to locate __cfi_slowpath in %s\n",
                libdl_path);
        return;
    }

    if (patch_instruction_to_ret(insn) != 0) {
        patched = 1;
        fprintf(stderr, "libhybris: WARNING mprotect failed while patching __cfi_slowpath\n");
        return;
    }

    patched = 1;
    fprintf(stderr, "libhybris: patched __cfi_slowpath in bionic libdl.so\n");
}

#else /* !__aarch64__ */

void hybris_patch_bionic_cfi(void)
{
    /* Not implemented for this architecture. */
}

#endif
