/* -- ELF Code Injector by binoopang [binoopang@gmail.com]----------------------- */

#ifndef CODE_INJECTOR_C
#define CODE_INJECTOR_C 1

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <limits.h>
#include <sys/wait.h>

/* -- Memory mapping information structure -- */
typedef struct map_info_s{
	unsigned long begin;
	unsigned long end;
	char perm[8];
	unsigned long foo;
	char dev[8];
	unsigned int inode;
	char mapname[PATH_MAX];
} MAP_INFO, *PMAP_INFO;

PMAP_INFO map[128];

/* -- remote injection help functions -- */
void restore_code(int pid, unsigned long base_address, long original_code[], struct user_regs_struct *regs, int);
unsigned int execute_code(int pid, unsigned char code[], int);
unsigned int execute_exit_code(int pid, unsigned char code[], int);
int get_codelen(unsigned char code[]);
PMAP_INFO* get_map_info(int pid);
/* -- ptrace help functions -- */
void ptrace_detach(int pid);
void ptrace_cont(int pid);
void ptrace_setregs(int pid, struct user_regs_struct*);
void ptrace_getregs(int pid, struct user_regs_struct*);
void ptrace_attach(int pid);
char *read_str(int pid, unsigned long addr, int len);
void *read_data(int pid, unsigned long addr, void *vptr, int len);
void write_data(int pid, unsigned long target_address, unsigned char code[], int len);

/* -- Restore original code -- */
void restore_code(int pid, unsigned long base_address, long original_code[], 
		struct user_regs_struct *regs, int CODE_LENGTH) 
{
	int i, j;
				
	for(i=0, j=0; i<CODE_LENGTH/4 ; i++, j+=4)
	{
		ptrace(PTRACE_POKEDATA, pid, base_address+j,
										original_code[i]);
#ifdef __print__
		printf("[-] RESTORED CODE : 0x%lx :  %lx\n",
										base_address+j, 
										ptrace(PTRACE_PEEKDATA, 
										pid, base_address+j, NULL));
#endif
	}

	ptrace_setregs(pid, regs);
}

/* -- Execute new code -- */
unsigned int execute_code(int pid, unsigned char code[], int CODE_LENGTH)
{
	long reg_eip;
	unsigned int ret;
	unsigned char original_code[128];
	int i, j; 
	struct user_regs_struct regs;
	struct user_regs_struct regs_ret;
	unsigned int base_address = 0x8048000;

	ptrace_attach(pid);

	ptrace_getregs(pid, &regs);
	reg_eip = regs.eip;

	regs.eip = base_address+2;
	ptrace_setregs(pid, &regs);

	for(i=0, j=0 ; i<CODE_LENGTH/4 ; i++, j+=4)
	{
		original_code[i] = ptrace(PTRACE_PEEKDATA, pid, 
										(caddr_t)base_address+j, NULL);
#ifdef __print__
		printf("[-] OLD CODE : 0x%lx : %lx\n",
										base_address+j, original_code[i]);
#endif
	}

	for(i=0 ; i<CODE_LENGTH ; i+=4)
	{
		ptrace(PTRACE_POKEDATA, pid, base_address+i,
										*(int*)(code+i));
#ifdef __print__
		printf("[-] NEW CODE : 0x%lx :  %lx\n",
										base_address+i, 
										ptrace(PTRACE_PEEKDATA, 
										pid, base_address+i, NULL));
#endif
	}

	ptrace_cont(pid);

	ptrace_getregs(pid, &regs_ret);
	ret = (unsigned int)regs_ret.eax;

	regs.eip=reg_eip;

	restore_code(pid, base_address, original_code, &regs, CODE_LENGTH);

	ptrace_detach(pid);

	return ret;
}

unsigned int execute_exit_code(int pid, unsigned char code[], int CODE_LENGTH)
{
	long reg_eip;
	unsigned int ret;
	unsigned char original_code[128];
	int i, j; 
	struct user_regs_struct regs;
	struct user_regs_struct regs_ret;
	unsigned int base_address = 0x8048000;

	ptrace_attach(pid);

	ptrace_getregs(pid, &regs);
	reg_eip = regs.eip;

	regs.eip = base_address+2;
	ptrace_setregs(pid, &regs);

	for(i=0, j=0 ; i<CODE_LENGTH/4 ; i++, j+=4)
	{
		original_code[i] = ptrace(PTRACE_PEEKDATA, pid, 
										(caddr_t)base_address+j, NULL);
#ifdef __print__
		printf("[-] OLD CODE : 0x%lx : %lx\n",
										base_address+j, original_code[i]);
#endif
	}

	for(i=0 ; i<CODE_LENGTH ; i+=4)
	{
		ptrace(PTRACE_POKEDATA, pid, base_address+i,
										*(int*)(code+i));
#ifdef __print__
		printf("[-] NEW CODE : 0x%lx :  %lx\n",
										base_address+i, 
										ptrace(PTRACE_PEEKDATA, 
										pid, base_address+i, NULL));
#endif
	}

	// If we execute exit(), we need not wait
	ptrace(PTRACE_CONT , pid , NULL , NULL);
}

void write_data(int pid, unsigned long target_address, unsigned char code[], int len)
{
	int i; 

	for(i=0 ; i<len ; i+=4)
	{
		ptrace(PTRACE_POKEDATA, pid, target_address+i,
										*(int*)(code+i));
	}
}

/* -- retrieve remote process's memory mapping information -- */
PMAP_INFO* get_map_info(int pid)
{
	char fname[PATH_MAX];
	unsigned long writable=0, total=0, shared=0;
	int i=0;
	FILE *f;

	sprintf(fname, "/proc/%ld/maps", (long)pid);

	f = fopen(fname, "r");

	if(!f)
	{
#ifdef __print__
		fprintf(stderr, "[-] fopen error ;(\n");
#endif
		exit(-1);
	}

	while(!feof(f)){
		char buf[PATH_MAX+100], perm[5], dev[6], mapname[PATH_MAX];
		unsigned long begin, end, size, inode, foo;
		int n;

		map[i] = malloc(sizeof(MAP_INFO));

		if(fgets(buf, sizeof(buf), f) == 0)
			break;

		mapname[0] = '\0';
		sscanf(buf, "%lx-%lx %4s %lx %5s %ld %s", &begin, &end, perm,
				&foo, dev, &inode, mapname);

		map[i]->begin = begin;
		map[i]->end = end;
		strcpy(map[i]->perm, perm);
		map[i]->foo = foo;
		strcpy(map[i]->dev, dev);
		map[i]->inode = inode;
		strcpy(map[i]->mapname, mapname);

		i++;
	}

	map[i] = (PMAP_INFO)NULL;

	/* -- we should free before termination of program -- */
	return map;
}

int get_codelen(unsigned char code[])
{
	int i=0;
	while(code[i] != 0xcc)
		i++;

	return i+1;
}

void * read_data(int pid, unsigned long addr, void *vptr, int len)
{
	int i, count;
	long word;
	unsigned long *ptr = (unsigned long *)vptr;

	count = i = 0;

	while (count < len){
		word = ptrace(PTRACE_PEEKTEXT, pid, addr+count, NULL);
		count += 4;
		ptr[i++] = word;
	}
}

char *read_str(int pid, unsigned long addr, int len)
{
	char *ret = calloc(32, sizeof(char));
	read_data(pid, addr, ret, len);
	return ret;
}

void ptrace_attach(int pid)
{
  if((ptrace(PTRACE_ATTACH , pid , NULL , NULL)) < 0) {
   perror("ptrace_attach");
   exit(-1);
  }

  waitpid(pid , NULL , WUNTRACED);
}

void ptrace_getregs(int pid, struct user_regs_struct *regs)
{
  if((ptrace(PTRACE_GETREGS, pid, NULL, regs)) < 0)
  {
          perror("ptrace_getregs");
          exit(-1);
  }
}

void ptrace_setregs(int pid, struct user_regs_struct *regs)
{
  if((ptrace(PTRACE_SETREGS, pid, NULL, regs)) < 0)
  {
          perror("ptrace_getregs");
          exit(-1);
  }
}

void ptrace_cont(int pid)
{
  int s;
  if((ptrace(PTRACE_CONT , pid , NULL , NULL)) < 0) {
   perror("ptrace_cont");
   exit(-1);
  }

  while (!WIFSTOPPED(s)) waitpid(pid , &s , WNOHANG);
}


void ptrace_detach(int pid)
{
  if(ptrace(PTRACE_DETACH, pid , NULL , NULL) < 0) {
   perror("ptrace_detach");
   exit(-1);
  }
}

#endif
