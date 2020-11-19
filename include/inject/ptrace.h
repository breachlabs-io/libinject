#ifndef _INJ_PTRACE_H
#define _INJ_PTRACE_H

#include <stdint.h>
#include <sys/user.h>

#define REL32_SZ 5

static int inj_ptrace_attach(pid_t pid);
static int inj_ptrace_cont(pid_t pid);
static int inj_ptrace_getregs(pid_t pid, struct user_regs_struct *regs);
static int inj_ptrace_setregs(pid_t pid, struct user_regs_struct *regs);
static int inj_ptrace_peektext(pid_t pid, void *where, void *buf, size_t len);
static int inj_ptrace_poketext(pid_t pid, void *where, void *new_text,
	void *old_text, size_t len);
static int inj_ptrace_singlestep(pid_t pid);
static int inj_do_wait(const char *name);
static int32_t inj_compute_jmp(void *from, void *to);
static int inj_restore(pid_t pid, void *rip,
	struct user_regs_struct *oldregs, void *old_text);

void *inj_mmap(pid_t pid, void *addr, size_t length, int prot, 
	int flags, int fd, off_t offset);
int inj_munmap(pid_t pid, void *addr, size_t len);
int inj_mprotect(pid_t pid, void *addr, size_t len, int prot);
int inj_memread(pid_t pid, void *dest, void *src, size_t n);
int inj_memwrite(pid_t pid, void *dest, void *src, size_t n);
void *inj_malloc(pid_t pid, size_t size);
int inj_jump_with_stack(pid_t pid, void *jump_addr, void *stack_addr);

#endif // _INJ_PTRACE_H