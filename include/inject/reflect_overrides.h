#ifndef _INJ_REFLECT_OVERRIDES_H
#define _INJ_REFLECT_OVERRIDES_H

#include <elf.h>
#include <link.h>
#include <limits.h>
#include <arpa/inet.h>

#include <libreflect/reflect.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

/* ELF compatibility checks */
#if UINTPTR_MAX > 0xffffffff
#define ELFCLASS_NATIVE ELFCLASS64
#else
#define ELFCLASS_NATIVE ELFCLASS32
#endif

#define PAGE_FLOOR(addr) ((addr) & (-PAGE_SIZE))
#define PAGE_CEIL(addr) (PAGE_FLOOR((addr) + PAGE_SIZE - 1))

#define ELFDATA_NATIVE ((htonl(1) == 1) ? ELFDATA2MSB : ELFDATA2LSB)

extern char **environ;

void inj_map_elf(pid_t pid, const unsigned char *data, struct mapped_elf *obj);
void inj_execve(pid_t pid, const unsigned char *elf, char **argv, char **env);
void inj_stack_setup(pid_t pid, size_t *stack, size_t *real_stack, size_t stack_len, size_t base_offset,
	int argc, char **argv, char **env, size_t *auxv, ElfW(Ehdr) *exe, ElfW(Ehdr) *interp);
void inj_load_program_info(size_t *auxv, ElfW(Ehdr) *exe,
	ElfW(Ehdr) *real_exe, ElfW(Ehdr) *interp);
void inj_synthetic_auxv(size_t *auxv, size_t *real_auxv);

#endif // _INJ_REFLECT_OVERRIDES_H