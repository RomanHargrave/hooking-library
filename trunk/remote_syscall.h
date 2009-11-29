/* -- remote syscall by binoopang [binoopang@gmail.com]---------------------------- *
 * This file contains the remote system call proto types and some defines
 * And this remote system call is not Standard cause I modified some system call
 * For example If you want to use open system call. you should feed file path right?
 * But if remote process has not file path, you can not open file.
 * So, i feed file path string to remote process using remote_mmap ;)            -- */

#ifndef REMOTE_SYSCALL_H
#define REMOTE_SYSCALL_H 

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <link.h>
#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <asm/unistd.h>

#include "code_injector.c"

#define __x86_32__

/* -- x86 Assembly code -- */
#ifdef __x86_32__
#define INIT_STUB 	"\x55\x53\x56\x57\x31\xd2\x31\xf6\x31\xc9" 	// PUSH & XOR
#define FINI_STUB 	"\x5f\x5e\x5b\x5d\xcc"		 				// POP
#define syscall		"\xcd\x80"
#define movl_eax 	"\xb8"
#define movl_ebx 	"\xbb"
#define movl_ecx 	"\xb9"
#define movl_edx 	"\xba"
#define movl_esi 	"\xbe"
#define movl_edi 	"\xbf"
#define movl_ebp 	"\xbd"
#define nop			"\x90"
#endif

/* -- to more readable -- */
#define REG_EAX		1
#define REG_EBX		2
#define REG_ECX		3
#define REG_EDX		4
#define REG_ESI		5
#define REG_EDI		6
#define REG_EBP		7

/* -- machine code -- */
unsigned char machine_code[] =
	INIT_STUB
	movl_ebx "\x00\x00\x00\x00" // First arg
	movl_ecx "\x00\x00\x00\x00"
	movl_edx "\x00\x00\x00\x00"
	movl_esi "\x00\x00\x00\x00"
	movl_edi "\x00\x00\x00\x00"
	movl_ebp "\x00\x00\x00\x00" // Last arg
	movl_eax "\x00\x00\x00\x00"	// Set System call number
	syscall						// Interrupt!!
	FINI_STUB;


/* -- remote System calls -- */
int remote_exit(pid_t pid, int);
int remote_fork(pid_t pid);
int remote_read(pid_t pid, int fd, unsigned char* buf, int len);
int remote_write(pid_t pid, int fd, unsigned char* buf, int len);
int remote_open(pid_t pid, char *path, int flags);

void* remote_mmap(pid_t pid, void *start, size_t length, int prot, int flags, int fd, int offset);
int remote_munmap(pid_t pid, void *start, int size);
void set_reg(int reg, unsigned int val, char *code);

#include "remote_syscall.c"

#endif
