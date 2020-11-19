#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <inject/inject.h>
#include <inject/reflect_overrides.h>
#include <inject/ptrace.h>

// Non-multilib compatible, makes a mmap(2) allocation and copy of the ELF object
void inj_map_elf(pid_t pid, const unsigned char *data, struct mapped_elf *obj) {
	ElfW(Addr) dest = 0;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;

	unsigned char *mapping = MAP_FAILED; // target memory location
	unsigned char *local_mapping = MAP_FAILED;
	const unsigned char *source = 0;
	size_t len, virtual_offset = 0, total_to_map = 0;
	int ii, prot;

	// Locate ELF program and section headers
	ehdr = (ElfW(Ehdr) *)data;
	phdr = (ElfW(Phdr) *)(data + ehdr->e_phoff);

	// Go through once to get the end so we reserve enough memory
	for(ii = 0; ii < ehdr->e_phnum; ii++, phdr++) {
		if(phdr->p_type == PT_LOAD) {
			total_to_map = ((phdr->p_vaddr + phdr->p_memsz) > total_to_map
					? phdr->p_vaddr + phdr->p_memsz
					: total_to_map);
			dprint("total mapping is now %08zx based on %08zx seg at %p\n", total_to_map, phdr->p_memsz, (void *)phdr->p_vaddr);
		}
	}

	// Reset phdr
	phdr = (ElfW(Phdr) *)(data + ehdr->e_phoff);
	for(ii = 0; ii < ehdr->e_phnum; ii++, phdr++) {
		if(phdr->p_type == PT_LOAD) {
			if(mapping == MAP_FAILED) {
				mapping = inj_mmap(pid, NULL, PAGE_CEIL(total_to_map), PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
				if(mapping == MAP_FAILED) {
					dprint("Failed to mmap(): %s\n", strerror(errno));
					goto map_failed;
				}
				local_mapping = mmap(NULL, PAGE_CEIL(total_to_map), PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
				if(local_mapping == MAP_FAILED) {
					dprint("Failed to mmap(): %s\n", strerror(errno));
					goto map_failed;
				}
				memset(local_mapping, 0, PAGE_CEIL(total_to_map));
				inj_memwrite(pid, mapping, local_mapping, PAGE_CEIL(total_to_map));
				munmap(local_mapping, PAGE_CEIL(total_to_map));
				dprint("data @ %p, mapping @ %p\n", data, mapping);
				virtual_offset = (size_t) mapping;
				obj->ehdr = (ElfW(Ehdr) *) (virtual_offset + phdr->p_vaddr);
				obj->entry_point = virtual_offset + ehdr->e_entry;
			}
			source = data + phdr->p_offset;
			dest = virtual_offset + phdr->p_vaddr;
			len = phdr->p_filesz;
			dprint("memcpy(%p, %p, %08zx)\n", (void *)dest, source, len);
			inj_memwrite(pid, (void *)dest, (void *)source, len);

			prot = (((phdr->p_flags & PF_R) ? PROT_READ : 0) |
				((phdr->p_flags & PF_W) ? PROT_WRITE: 0) |
				((phdr->p_flags & PF_X) ? PROT_EXEC : 0));
			if(inj_mprotect(pid, (void *)PAGE_FLOOR(dest), PAGE_CEIL(phdr->p_memsz), prot) != 0) {
				goto mprotect_failed;
			}
		} else if(phdr->p_type == PT_INTERP) {
			// Since PT_INTERP must come before any PT_LOAD segments, store the
			// offset for now and add the base mapping at the end
			obj->interp = (char *) phdr->p_offset;
			if (phdr->p_vaddr) 
				obj->interp = (char *) phdr->p_vaddr;
		}

	}

	if(obj->interp) {
		obj->interp = (char *) virtual_offset + (size_t) obj->interp;
	}

	return;

mprotect_failed:
	inj_munmap(pid, mapping, PAGE_CEIL(total_to_map));

map_failed:
	obj->ehdr = MAP_FAILED;
}

void inj_execve(pid_t pid, const unsigned char *elf, char **argv, char **env) {
	int fd;
	struct stat statbuf;
	unsigned char *data = NULL;
	size_t argc, stack_len, base_offset;
	size_t *stack, *real_stack;

	struct mapped_elf exe = {0}, interp = {0};


	if (!is_compatible_elf((ElfW(Ehdr) *)elf)) {
		abort();
	}


	if (env == NULL) {
		env = environ;
	}

	inj_map_elf(pid, elf, &exe);
	if (exe.ehdr == MAP_FAILED) {
		dprint("Unable to map ELF file: %s\n", strerror(errno));
		abort();
	}

	if (exe.interp) {
		char *real_interp = (char *) calloc(1024, sizeof(char));
		if (inj_memread(pid, real_interp, exe.interp, 1024)) {
			dprint("Failed to read interp from process\n");
			abort();
		}

		// Load input ELF executable into memory
		fd = open(real_interp, O_RDONLY);
		if(fd == -1) {
			dprint("Failed to open %s: %s\n", real_interp, strerror(errno));
			abort();
		}

		if(fstat(fd, &statbuf) == -1) {
			dprint("Failed to fstat(fd): %s\n", strerror(errno));
			abort();
		}

		data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if(data == MAP_FAILED) {
			dprint("Unable to read ELF file in: %s\n", strerror(errno));
			abort();
		}
		close(fd);

		inj_map_elf(pid, data, &interp);
		munmap(data, statbuf.st_size);
		if (interp.ehdr == MAP_FAILED) {
			dprint("Unable to map interpreter for ELF file: %s\n", strerror(errno));
			abort();
		}
		dprint("Mapped ELF interp file in: %s\n", real_interp);
		free(real_interp);
	} else {
		interp = exe;
	}

	for (argc = 0; argv[argc]; argc++);

	stack_len = 2048 * PAGE_SIZE;
	base_offset = 2047 * PAGE_SIZE;
	stack = mmap(0, stack_len, PROT_READ|PROT_WRITE,
		MAP_ANONYMOUS|MAP_PRIVATE|MAP_GROWSDOWN, -1, 0);
	real_stack = inj_mmap(pid, 0, stack_len, PROT_READ|PROT_WRITE,
		MAP_ANONYMOUS|MAP_PRIVATE|MAP_GROWSDOWN, -1, 0);

	dprint("Allocated new stack %p\n", (void *)stack);

	inj_stack_setup(pid, stack, real_stack, stack_len, base_offset, argc, argv, env, NULL,
			exe.ehdr, interp.ehdr);
	dprint("Stack setup complete\n");
	munmap(stack, stack_len);

	inj_jump_with_stack(pid, (void *)interp.entry_point, (void *)real_stack + base_offset);
}

void inj_stack_setup(pid_t pid, size_t *stack, size_t *real_stack, size_t stack_len, size_t base_offset,
	int argc, char **argv, char **env, size_t *auxv, ElfW(Ehdr) *exe, ElfW(Ehdr) *interp) {
	size_t *stack_base;
	size_t *real_stack_base;
	size_t *auxv_base;
	size_t *real_auxv_base;
	ElfW(Ehdr) real_exe;

	int ii;
	int total_args_len = 0;
	off_t args_offset = 0;
	size_t *args_data;

	for (ii = 0; ii < argc; ii++) {
		total_args_len += strlen(argv[ii]) + 1;
	}

	for (ii = 0; env[ii]; ii++) {
		total_args_len += strlen(env[ii]) + 1;
	}

	args_data = inj_mmap(pid, NULL, total_args_len,
		PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (args_data == MAP_FAILED) {
		dprint("Failed to mmap args data\n");
		abort();
	}

	dprint("New stack: %p\n", (void *)real_stack + base_offset);

	stack_base = (void *) stack + base_offset;
	real_stack_base = (void *) real_stack + base_offset;

	stack_base[0] = argc;
	dprint("  0x%08zx\n", stack_base[0]);

	for (ii = 0; ii < argc; ii++) {
		if (inj_memwrite(pid, (void *)args_data + args_offset, argv[ii], strlen(argv[ii])+1)) {
			dprint("Failed to write arg to mmap");
			abort();
		}
		stack_base[1 + ii] = (size_t)args_data + args_offset;
		dprint("  0x%08zx\n", stack_base[1 + ii]);
		args_offset += strlen(argv[ii]) + 1;
	}
	stack_base[1 + ii] = 0;
	dprint("  0x%08zx\n", stack_base[1 + ii]);

	for (ii = 0; env[ii]; ii++) {
		if (inj_memwrite(pid, (void *)args_data + args_offset, env[ii], strlen(env[ii])+1)) {
			dprint("Failed to write env to mmap");
			abort();
		}
		stack_base[1 + argc + ii] = (size_t)args_data + args_offset;
		dprint("  0x%08zx\n", stack_base[1 + argc + ii]);
		args_offset += strlen(env[ii]) + 1;
	}
	stack_base[1 + argc + ii] = 0;
	dprint("  0x%08zx\n", stack_base[1 + argc + ii]);

	auxv_base = stack_base + 1 + argc + ii + 1;
	real_auxv_base = real_stack_base + 1 + argc + ii + 1;

	if(auxv) {
		for (ii = 0; auxv[ii]; ii++) {
			auxv_base[ii] = auxv[ii];
		}
		auxv_base[ii] = AT_NULL;
		auxv_base[ii + 1] = 0;
	} else {
		inj_synthetic_auxv(auxv_base, real_auxv_base);
	}

	if (inj_memread(pid, &real_exe, exe, sizeof(ElfW(Ehdr)))) {
		dprint("Failed to read real exe\n");
		abort();
	}

	inj_load_program_info(auxv_base, exe, &real_exe, interp);

	if (inj_memwrite(pid, real_stack, stack, stack_len)) {
		dprint("Copy of shadow stack to real stack failed\n");
		abort();
	}
}

void inj_load_program_info(size_t *auxv, ElfW(Ehdr) *exe,
	ElfW(Ehdr) *real_exe, ElfW(Ehdr) *interp) {
	int ii;
	size_t exe_loc = (size_t) exe, interp_loc = (size_t) interp;

	for (ii = 0; auxv[ii]; ii += 2) {
		switch (auxv[ii]) {
			case AT_BASE:
				auxv[ii + 1] = interp_loc;
				break;
			case AT_PHDR:
				// When this points to a different place than the executable in
				// AT_BASE, the dynamic linker knows that another program is
				// pre-loaded by whoever invoked it
				auxv[ii + 1] = exe_loc + real_exe->e_phoff;
				break;
			case AT_ENTRY:
				// If the exe is position-independent, `e_entry` is an offset
				// and we need to add it to the base of image
				auxv[ii + 1] = (real_exe->e_entry < exe_loc ? exe_loc + real_exe->e_entry : real_exe->e_entry);
				break;
			case AT_PHNUM:
				auxv[ii + 1] = real_exe->e_phnum;
				break;
			case AT_PHENT:
				auxv[ii + 1] = real_exe->e_phentsize;
				break;
			case AT_SECURE:
				auxv[ii + 1] = 0;
				break;
		}
	}
}

void inj_synthetic_auxv(size_t *auxv, size_t *real_auxv) {
	auxv[0] = AT_BASE;
	auxv[2] = AT_PHDR;
	auxv[4] = AT_ENTRY;
	auxv[6] = AT_PHNUM;
	auxv[8] = AT_PHENT;
	auxv[10] = AT_PAGESZ; auxv[11] = PAGE_SIZE;
	auxv[12] = AT_SECURE;
    // Required for stack cookies on glibc, hope your payload doesn't get popped
	auxv[14] = AT_RANDOM; auxv[15] = (size_t)real_auxv;
	auxv[16] = AT_NULL; auxv[17] = 0;
}