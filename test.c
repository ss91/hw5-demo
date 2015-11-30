#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include "err.h"

#define BASE_ADDR ((void*)0x01000000)
static int PAGE_SIZE;
static int print_region(const char *str);
static int print_maps(void);


static int print_maps(void);
static void pr_errno(const char *msg)
{
	printf("error: %s, %s", strerror(errno), msg);
}

static void pr_err(const char *msg)
{
	printf("error: %s", msg);
}

static int test_1(void)
{
	return print_region("..........");
}

static int test_2(void)
{
	return print_region("1111111111");
}

static int test_3(void)
{
	return print_region(".1.1.1.1.1");
}

static int test_4(void)
{
	return print_region("22222.....");
}

static int test_5(void)
{
	return print_region("1111..2222");
}

static int test_6(void)
{

		int i, res;
		char *buf = malloc(2001 * sizeof(char));
	
		if (!buf) {
				pr_errno("Failed to allocate memory");
				return -1;
			}
		
			for (i = 0; i < 2000; ++i)
				buf[i] = '.';
		
			buf[2000] = '\0';
		
			res = print_region(buf);
		
			free(buf);
		
			return res;
}

static int test_7(void)
{
		char *p = NULL;
		char *_p = NULL;
		size_t len = PAGE_SIZE;
		size_t i;
	
		for (;;) {
				_p = realloc(p, len);
				if (!_p)
					break;
				p = _p;
				len *= 2;
			}
		
			if (!p)
				pr_errno("cannot alloc memory");
		
			printf("allocted %u bytes. Commence destruction."
					"(device may freeze for a bit)\n", len);
		
			for (i = 0; i < len; i += PAGE_SIZE)
				p[i] = 0;
		
			printf("Should be unreachable\n");
		
		 	return 0;
}

static int recurse_print_region(const char *str, int num_pages, int level, char *page)
{
		int ret, i;
		char map;
		pid_t pid;
	
		map = level + '0';
		if (level == 10)
			map = 'X';
	
		for (i = 0; i < num_pages; i++) {
				/* writing to page breaks COW */
				if (str[i] == map) {
						page[i * PAGE_SIZE] = 0;
					}
				}
			
				/* base case */
				if (level <= 1) {
						print_maps();
						return 0;
					}
				
					pid = fork();
					if (pid < 0)
						pr_errno("fork() failed");
				
					if (pid == 0)
						sleep(1000);
				
					ret = recurse_print_region(str, num_pages, level - 1, page);
				
					kill(pid, SIGKILL);
				
					return ret;
}
				
static int print_region(const char *str)
{				
						int num_pages = strlen(str);
						int ret;
						char *page;
						int total_sz = num_pages * PAGE_SIZE;
					
						page = mmap(BASE_ADDR, total_sz, PROT_READ | PROT_WRITE,
							   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
						if (page == MAP_FAILED)
							pr_errno("cannot mmap()");
					
						ret = recurse_print_region(str, num_pages, 10, page);
					
						munmap(page, total_sz);
						return ret;
}

int main(int argc, char **argv)
{
	/*
	 * Change this main function as you see fit.
	 */
		int res;
	
		PAGE_SIZE = getpagesize();
	
		res = test_1();
		if (res != 0)
			return -1;
	
		res = test_2();
		if (res != 0)
			return -1;
	
		res = test_3();
		if (res != 0)
			return -1;
	
		res = test_4();
		if (res != 0)
			return -1;
	
		res = test_5();
		if (res != 0)
			return -1;
	
		res = test_6();
		if (res != 0)
			return -1;
	
		res = test_7();
		if (res != 0)
			return -1;
	
		return 0;



}

static int print_maps(void)
{
	/*
	 * You may not modify print_maps().
	 * Every test should call print_maps() once.
	 */
	char *path;
	char str[25000];
	int fd;
	int r, w;

	path = "/proc/self/maps";
	printf("%s:\n", path);

	fd = open(path, O_RDONLY);

	if (fd < 0)
		pr_errno(path);

	r = read(fd, str, sizeof(str));

	if (r < 0)
		pr_errno("cannot read the mapping");

	if (r == sizeof(str))
		pr_err("mapping too big");

	while (r) {
		w = write(1, str, r);
		if (w < 0)
			pr_errno("cannot write to stdout");
		r -= w;
	}

	return 0;
}
