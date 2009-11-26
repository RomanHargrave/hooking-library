/* -- remote syscall by binoopang [binoopang@gmail.com]---------------------------- */

#ifndef REMOTE_SYSCALL_C
#define REMOTE_SYSCALL_C 1

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
	movl_eax "\x00\x00\x00\x00"
	syscall
	FINI_STUB;


/* -- remote System calls -- */
void* remote_mmap(pid_t pid, void *start, size_t length, int prot, int flags, int fd, int offset);
int remote_open(pid_t pid, char *path, int flags);
int remote_munmap(pid_t pid, void *start, int size);
void set_arg(int reg, unsigned int val, char *code);

/* -- Remote munmap function -- */
int remote_munmap(pid_t pid, void *start, int size)
{
	int len, ret;

	set_arg(REG_EAX, __NR_munmap, machine_code);
	set_arg(REG_EBX, (unsigned int)start, machine_code);
	set_arg(REG_ECX, size, machine_code);

	len = get_codelen(machine_code);

	ret = (int)execute_code(pid, machine_code, len);

	return ret;
}

/* -- remote close function -- */
int remote_close(pid_t pid, int fd)
{
	int len, ret;

	set_arg(REG_EAX, __NR_close, machine_code);
	set_arg(REG_EBX, fd, machine_code);

	len = get_codelen(machine_code);

	ret = (int)execute_code(pid, machine_code, len);

	return ret;
}

/* -- Remote open function -- */
int remote_open(pid_t pid, char *path, int flags)
{
	int len, ret;
	unsigned long ptr;

	ptr = (unsigned long)remote_mmap(pid, NULL, 128, PROT_READ|PROT_WRITE, 
			MAP_PRIVATE|MAP_ANONYMOUS,-1,0);

	if(ptr > 0)
	{
		ptrace_attach(pid);

		write_data(pid, ptr, path, strlen(path));
		ptrace_detach(pid);

		set_arg(REG_EAX, __NR_open, machine_code);
		set_arg(REG_EBX, (unsigned int)ptr, machine_code);
		set_arg(REG_ECX, flags, machine_code);

		len = get_codelen(machine_code);

		ret = execute_code(pid, machine_code, len);

		// release string memory space
		remote_munmap(pid, (void*)ptr, 128);
	}

	return ret;

}

/* -- Remote mmap function -- */
void* remote_mmap(pid_t pid, void *start, size_t length, int prot, int flags, int fd, int offset)
{
	int len;
	void* ret;

	set_arg(REG_EAX, __NR_mmap2, machine_code);
	set_arg(REG_EBX, (unsigned int)start, machine_code);
	set_arg(REG_ECX, length, machine_code);
	set_arg(REG_EDX, prot, machine_code);
	set_arg(REG_ESI, flags, machine_code);
	set_arg(REG_EDI, fd, machine_code);
	set_arg(REG_EBP, offset, machine_code);

	len = get_codelen(machine_code);

	ret = (void*)execute_code(pid, machine_code, len);

	return ret;
}

/* -- set movl operand -- */
void set_arg(int reg, unsigned int val, char *code)
{
	switch(reg){
		case REG_EBX:
			memcpy(code+11, (void*)&val, 4);
			break;
		case REG_ECX:
			memcpy(code+16, (void*)&val, 4);
			break;
		case REG_EDX:
			memcpy(code+21, (void*)&val, 4);
			break;
		case REG_ESI:
			memcpy(code+26, (void*)&val, 4);
			break;
		case REG_EDI:
			memcpy(code+31, (void*)&val, 4);
			break;
		case REG_EBP:
			memcpy(code+36, (void*)&val, 4);
			break;
		case REG_EAX:
			memcpy(code+41, (void*)&val, 4);
			break;
	}
}

#endif
