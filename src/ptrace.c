#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <inject/ptrace.h>
#include <inject/inject.h>

static int inj_ptrace_attach(pid_t pid) {
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
		perror("PTRACE_ATTACH");
		return -1;
	}

	if (waitpid(pid, 0, WSTOPPED) == -1) {
		perror("wait");
		return -1;
	}

	return 0;
}

static int inj_ptrace_cont(pid_t pid) {
	dprint("continuing execution\n");
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	return inj_do_wait("PTRACE_CONT");
}

static int inj_ptrace_getregs(pid_t pid, struct user_regs_struct *regs) {
	if (ptrace(PTRACE_GETREGS, pid, NULL, regs)) {
		perror("PTRACE_GETREGS");
		return -1;
	}
	return 0;
}

static int inj_ptrace_setregs(pid_t pid, struct user_regs_struct *regs) {
	if (ptrace(PTRACE_SETREGS, pid, NULL, regs)) {
		perror("PTRACE_SETREGS");
		return -1;
	}
	return 0;
}

static int inj_ptrace_peektext(pid_t pid, void *where, void *buf, size_t len) {
	// if (len % sizeof(void *) != 0) {
	// 	printf("invalid len %d, not a multiple of %zd\n", len, sizeof(void *));return -1;
	// }

	long peek_data;
	for (size_t copied = 0; copied < len; copied += sizeof(peek_data)) {
		errno = 0;
		peek_data = ptrace(PTRACE_PEEKTEXT, pid, where + copied, NULL);
		if (peek_data == -1 && errno) {
			perror("PTRACE_PEEKTEXT");
			return -1;
		}
		memmove(buf + copied, &peek_data, sizeof(peek_data));
	}
	return 0;
}

static int inj_ptrace_poketext(pid_t pid, void *where, void *new_text,
	void *old_text, size_t len) {
	// if (len % sizeof(void *) != 0) {
	// 	printf("invalid len %d, not a multiple of %zd\n", len, sizeof(void *));return -1;
	// }

	long poke_data;
	for (size_t copied = 0; copied < len; copied += sizeof(poke_data)) {
		memmove(&poke_data, new_text + copied, sizeof(poke_data));
		if (old_text != NULL) {
			errno = 0;
			long peek_data = ptrace(PTRACE_PEEKTEXT, pid, where + copied, NULL);
			if (peek_data == -1 && errno) {
				perror("PTRACE_PEEKTEXT");
				return -1;
			}
			memmove(old_text + copied, &peek_data, sizeof(peek_data));
		}
		if (ptrace(PTRACE_POKETEXT, pid, where + copied, (void *)poke_data) < 0) {
			perror("PTRACE_POKETEXT");
			return -1;
		}
	}
	return 0;
}

static int inj_ptrace_singlestep(pid_t pid) {
	if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
		perror("PTRACE_SINGLESTEP");
		return -1;
	}
	return inj_do_wait("PTRACE_SINGLESTEP");
}

static int inj_do_wait(const char *name) {
	int status;
	if (wait(&status) == -1) {
		perror("wait");
		return -1;
	}
	if (WIFSTOPPED(status)) {
		if (WSTOPSIG(status) == SIGTRAP) {
			return 0;
		}
		printf("%s unexpectedly got status %s\n", name, strsignal(status));
		return -1;
	}
	printf("%s got unexpected status %d\n", name, status);
	return -1;
}

static int32_t inj_compute_jmp(void *from, void *to) {
	int64_t delta = (int64_t)to - (int64_t)from - REL32_SZ;
	if (delta < INT_MIN || delta > INT_MAX) {
		printf("cannot do relative jump of size %li; did you compile with -fPIC?\n",
			delta);
		exit(1);
	}
	return (int32_t)delta;
}

static int inj_restore(pid_t pid, void *rip,
	struct user_regs_struct *origregs, void *orig_text) {
	struct user_regs_struct newregs;
	uint8_t new_text[8];
	uint8_t old_text[8];
	void *old_text_rip;

	if (inj_ptrace_getregs(pid, &newregs)) {
		goto fail;
	}
	old_text_rip = (void *)newregs.rip;
	newregs.rax = (long)rip;
	if (inj_ptrace_setregs(pid, &newregs)) {
		goto fail;
	}

	new_text[0] = 0xff; // JMP %rax
	new_text[1] = 0xe0; // JMP %rax
	inj_ptrace_poketext(pid, (void *)newregs.rip, new_text, old_text, sizeof(new_text));

	dprint("jumping back to original rip\n");
	if (inj_ptrace_singlestep(pid)) {
		goto fail;
	}
	if (inj_ptrace_getregs(pid, &newregs)) {
		goto fail;
	}

	if (newregs.rip == (long)rip) {
		dprint("successfully jumped back to original %%rip at %p\n", rip);
	} else {
		printf("unexpectedly jumped to %p (expected to be at %p)\n",
			(void *)newregs.rip, rip);
		goto fail;
	}

	dprint("restoring original text at %p\n", old_text_rip);
	inj_ptrace_poketext(pid, old_text_rip, old_text, NULL, sizeof(old_text));

	dprint("restoring original text at %p\n", rip);
	inj_ptrace_poketext(pid, rip, orig_text, NULL, sizeof(orig_text));

	dprint("restoring original registers\n");
	if (inj_ptrace_setregs(pid, origregs)) {
		goto fail;
	}

	dprint("detaching\n");
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		perror("PTRACE_DETACH");
		goto fail;
	}

	return 0;

fail:
	dprint("inj_restore failed\n");
	inj_ptrace_poketext(pid, rip, orig_text, NULL, sizeof(orig_text));
	return -1;
}

void *inj_mmap(pid_t pid, void *addr, size_t length, int prot, 
	int flags, int fd, off_t offset) {
	struct user_regs_struct origregs;
	struct user_regs_struct newregs;
	uint8_t orig_text[8];
	uint8_t new_text[8];
	void *rip;
	void *mmap_memory;

	if (inj_ptrace_attach(pid)) {
		goto fail_detach;
	}

	if (inj_ptrace_getregs(pid, &origregs)) {
		goto fail_detach;
	}
	rip = (void *)origregs.rip;
	dprint("their %%rip           %p\n", rip);

	memmove(&newregs, &origregs, sizeof(newregs));
	newregs.rax = 9; // mmap syscall
	newregs.rdi = (long)addr;
	newregs.rsi = length;
	newregs.rdx = prot;
	newregs.r10 = flags;
	newregs.r8 = fd;
	newregs.r9 = offset;

	new_text[0] = 0x0f; // SYSCALL
	new_text[1] = 0x05; // SYSCALL

	if (inj_ptrace_poketext(pid, rip, new_text, orig_text, sizeof(new_text))) {
		goto fail;
	}
	if (inj_ptrace_setregs(pid, &newregs)) {
		goto fail;
	}
	if (inj_ptrace_singlestep(pid)) {
		goto fail;
	}
	if (inj_ptrace_getregs(pid, &newregs)) {
		goto fail;
	}

	mmap_memory = (void *)newregs.rax;
	if (mmap_memory == MAP_FAILED) {
		printf("failed to mmap\n");
		goto fail;
	}
	dprint("allocated memory at  %p\n", mmap_memory);

	inj_restore(pid, rip, &origregs, orig_text);

	return (void *)mmap_memory;

fail:
	dprint("inj_mmap failed\n");
	inj_ptrace_poketext(pid, rip, orig_text, NULL, sizeof(orig_text));
fail_detach:
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		perror("PTRACE_DETACH");
	}
	return MAP_FAILED;
}

int inj_munmap(pid_t pid, void *addr, size_t len) {
	struct user_regs_struct origregs;
	struct user_regs_struct newregs;
	uint8_t old_text[8];
	uint8_t new_text[8];
	void *rip;
	int ret;

	if (inj_ptrace_attach(pid)) {
		goto fail_detach;
	}

	if (inj_ptrace_getregs(pid, &origregs)) {
		goto fail_detach;
	}
	rip = (void *)origregs.rip;
	dprint("their %%rip           %p\n", rip);

	memmove(&newregs, &origregs, sizeof(newregs));
  	newregs.rax = 11; // munmap syscall
  	newregs.rdi = (long)addr;
  	newregs.rsi = len;

	new_text[0] = 0x0f; // SYSCALL
	new_text[1] = 0x05; // SYSCALL

	if (inj_ptrace_poketext(pid, rip, new_text, old_text, sizeof(new_text))) {
		goto fail;
	}
	if (inj_ptrace_setregs(pid, &newregs)) {
		goto fail;
	}
	dprint("making call to munmap\n");
	if (inj_ptrace_singlestep(pid)) {
		goto fail;
	}
	if (inj_ptrace_getregs(pid, &newregs)) {
		goto fail;
	}
	ret = (int)newregs.rax;
	dprint("munmap returned with status %d\n", ret);

	inj_restore(pid, rip, &origregs, old_text);

	return ret;

fail:
	dprint("inj_munmap failed\n");
	inj_ptrace_poketext(pid, rip, old_text, NULL, sizeof(old_text));
fail_detach:
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		perror("PTRACE_DETACH");
	}
	return -1;
}

int inj_mprotect(pid_t pid, void *addr, size_t len, int prot) {
	struct user_regs_struct origregs;
	struct user_regs_struct newregs;
	uint8_t old_text[8];
	uint8_t new_text[8];
	void *rip;
	int ret;

	if (inj_ptrace_attach(pid)) {
		goto fail_detach;
	}

	if (inj_ptrace_getregs(pid, &origregs)) {
		goto fail_detach;
	}
	rip = (void *)origregs.rip;
	dprint("their %%rip           %p\n", rip);

	memmove(&newregs, &origregs, sizeof(newregs));
  	newregs.rax = 10; // mprotect syscall
  	newregs.rdi = (long)addr;
  	newregs.rsi = len;
  	newregs.rdx = prot;

	new_text[0] = 0x0f; // SYSCALL
	new_text[1] = 0x05; // SYSCALL

	if (inj_ptrace_poketext(pid, rip, new_text, old_text, sizeof(new_text))) {
		goto fail;
	}
	if (inj_ptrace_setregs(pid, &newregs)) {
		goto fail;
	}
	dprint("making call to mprotect\n");
	if (inj_ptrace_singlestep(pid)) {
		goto fail;
	}
	if (inj_ptrace_getregs(pid, &newregs)) {
		goto fail;
	}
	ret = (int)newregs.rax;
	dprint("mprotect returned with status %d\n", ret);

	inj_restore(pid, rip, &origregs, old_text);

	return ret;

fail:
	dprint("inj_mprotect failed\n");
	inj_ptrace_poketext(pid, rip, old_text, NULL, sizeof(old_text));
fail_detach:
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		perror("PTRACE_DETACH");
	}
	return -1;
}

int inj_memread(pid_t pid, void *dest, void *src, size_t n) {
	if (inj_ptrace_attach(pid)) {
		goto fail_detach;
	}

	if (inj_ptrace_peektext(pid, src, dest, n)) {
		goto fail_detach;
	}
	dprint("Read %d bytes into %p\n", n, dest);

	dprint("detaching\n");
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		perror("PTRACE_DETACH");
		return -1;
	}

	return 0;

fail_detach:
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		perror("PTRACE_DETACH");
	}
	return -1;
}

int inj_memwrite(pid_t pid, void *dest, void *src, size_t n) {
	if (inj_ptrace_attach(pid)) {
		goto fail_detach;
	}

	if (inj_ptrace_poketext(pid, dest, src, NULL, n)) {
		goto fail_detach;
	}
	dprint("Wrote %d bytes to %p\n", n, dest);

	dprint("detaching\n");
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		perror("PTRACE_DETACH");
		return -1;
	}

	return 0;

fail_detach:
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		perror("PTRACE_DETACH");
	}
	return -1;
}

int inj_jump_with_stack(pid_t pid, void *jump_addr, void *stack_addr) {
	struct user_regs_struct origregs;
	struct user_regs_struct newregs;
	uint8_t new_text[8];
	void *rip;
	void *rsp;

	if (inj_ptrace_attach(pid)) {
		goto fail_detach;
	}

	if (inj_ptrace_getregs(pid, &origregs)) {
		goto fail_detach;
	}
	rip = (void *)origregs.rip;
	dprint("their %%rip           %p\n", rip);
	rsp = (void *)origregs.rsp;
	dprint("their %%rsp           %p\n", rsp);

	memmove(&newregs, &origregs, sizeof(newregs));
	newregs.rax = (long)jump_addr;
	newregs.rdx = 0;
	newregs.rsp = (long)stack_addr;

	new_text[0] = 0xff; // JMP %rax
  	new_text[1] = 0xe0; // JMP %rax

	if (inj_ptrace_poketext(pid, rip, new_text, NULL, sizeof(new_text))) {
		goto fail_detach;
	}
	if (inj_ptrace_setregs(pid, &newregs)) {
		goto fail_detach;
	}
	dprint("Jumping to addr %p\n", jump_addr);
	if (inj_ptrace_singlestep(pid)) {
		goto fail_detach;
	}
	if (inj_ptrace_getregs(pid, &newregs)) {
		goto fail_detach;
	}

	if ((void *)newregs.rip == jump_addr) {
		dprint("successfully jumped to jump address %p\n", jump_addr);
	} else {
		printf("unexpectedly jumped to %p (expected to be at %p)\n",
           (void *)newregs.rip, jump_addr);
		goto fail_detach;
	}

	if ((void *)newregs.rsp == stack_addr) {
		dprint("successfully set the stack address %p\n", stack_addr);
	} else {
		printf("unexpectedly get stack address of %p (expected to be at %p)\n",
           (void *)newregs.rsp, stack_addr);
		goto fail_detach;
	}

	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		perror("PTRACE_DETACH");
		return -1;
	}

	return 0;

fail_detach:
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		perror("PTRACE_DETACH");
	}
	return -1;
}