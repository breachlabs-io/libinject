#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <limits.h>

#include <inject/inject.h>
#include <inject/ptrace.h>
#include <inject/reflect_overrides.h>

int main(int argc, char **argv)
{
	pid_t pid;
	int fd;
	struct stat statbuf;
	unsigned char *data = NULL;

	if(argc < 3) {
		printf("Usage: %s [pid] [elf]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	pid = atoi(argv[1]);

	fd = open(argv[2], O_RDONLY);
	if(fd == -1) {
		printf("Failed to open %s: %s\n", argv[2], strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(fstat(fd, &statbuf) == -1) {
		printf("Failed to fstat(fd): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(data == MAP_FAILED) {
		printf("Unable to read ELF file in: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	close(fd);

	inj_execve(pid, data, argv + 2, NULL);
	// pid_t pid = atoi(argv[1]);
	// void *data = inj_mmap(pid, NULL, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	// printf("data: %p\n", data);
	// int err = inj_munmap(pid, data, PAGE_SIZE);

	return 0;
}