/* ELF Shared Object Loader by binoopang [binoopang@gmail.com] ----- *
 * This Program is Shared object loader. You can Inject new Shared Object
 * into another process while running.
 * First argument is Process ID and the another is Shared Object Path
 * a second argument of dlopen is fixed to RTLD_LAZY           ----- */

#include <stdio.h>
#include <stdlib.h>
#include "remote_syscall.h"
#include "ELF_analyzer.c"

/* -- Machine code -- */
unsigned char dlopen_code[] =
	push 		"\x02\x00\x00\x00"	// Second Argument
	push 		"\x00\x00\x00\x00"	// First Argument
	movl_ecx 	"\x00\x00\x00\x00"	// Set Function Pointer
	call_ecx						// Call dlopen
	add_esp 	"\x8"				// Clean stack
	trap;

char *get_object_name(const char *);
void *print_mapped_info(int pid, char* object);

/* -- Entry point!! -- */
int main(int argc, char **argv)
{
	int flag=0, ret, i=0, len;
	long dlopen_addr, ptr;
	char str[128];
	void *handle = NULL;
	Elf32_Sym* sym = NULL;
	PMAP_INFO *map = NULL;
	map = get_map_info(atoi(argv[1]));	

	while(map[i]!=NULL){
		if(strstr(map[i]->mapname, "libdl") && strstr(map[i]->perm, "x")){
			flag=1;
			break;
		}
		i++;
	}

	if(flag==0)
	{
		fprintf(stderr, "Target process has no libdl ;(\n");
		exit(-1);
	}

	// retrieve dlopen's symbol structure pointer 
	sym = get_dynsymbol_value(map[i]->mapname, "dlopen");
	// make virtual memory address
	dlopen_addr = map[i]->begin + sym->st_value;

	printf("[*] dlopen address : 0x%lx\n", dlopen_addr);
	// allocate memory to save strings
	ptr = (long)remote_mmap(atoi(argv[1]), (void*)NULL, 8096,
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	printf("[*] Temporary Memory allocated at 0x%lx\n", ptr);

	// write file path into target process
	printf("[*] writing shared object path at 0x%lx\n", ptr);
	ptrace_attach(atoi(argv[1]));
	write_data(atoi(argv[1]), ptr, argv[2], strlen(argv[2]));
	ptrace_detach(atoi(argv[1]));

	// set dlopen's argument
	memcpy(dlopen_code+6, &ptr, 4);
	memcpy(dlopen_code+11, &dlopen_addr, 4);

	// calculate code length
	len = get_codelen(dlopen_code);

	// execute dlopen
	printf("[*] Executing dlopen()\n");
	handle = (void*)execute_code(atoi(argv[1]), dlopen_code, len);

	if(handle)
		printf("[*] Shared object load sucessfully\n");
	else
		printf("[*] Shared object load failed\n");

	// release memory
	printf("[*] release temporary memory\n");
	remote_munmap(atoi(argv[1]), (void*)ptr, 8096);

	while(map[i]!=NULL){
		if(strstr(map[i]->mapname, "libdl") && strstr(map[i]->perm, "x")){
			flag=1;
			break;
		}
		i++;
	}

	print_mapped_info(atoi(argv[1]), get_object_name(argv[2]));

	printf("[*] done\n");
	get_object_name(argv[2]);
	return 0;
}

void *print_mapped_info(int pid, char *object)
{
	int i=0;
	PMAP_INFO *map = NULL;
	map = get_map_info(pid);	

	printf("[*] Here is the New Shared object mapped info ==\n");

	while(map[i]!=NULL){
		if(strstr(map[i]->mapname, object)){
			printf("[-] 0x%lx - 0x%lx %s %s\n",
					map[i]->begin, map[i]->end, map[i]->perm,
					map[i]->mapname);
		}
		free(map[i++]);
	}

}
char *get_object_name(const char *path)
{
	char *ptr;
	int len = strlen(path)-1;
	while(path[len]!='/')
		len--;

	ptr = (char*)path+len+1;

	return ptr;
}
