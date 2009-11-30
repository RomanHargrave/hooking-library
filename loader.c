/* ELF Shared Object Loader by binoopang [binoopang@gmail.com] ----- *
 * This Program is Shared object loader. You can Inject new Shared Object
 * into another process while running.
 * First argument is Process ID and the another is Shared Object Path
 * a second argument of dlopen is fixed to RTLD_LAZY           ----- */

#include <stdio.h>
#include <stdlib.h>
#include "remote_syscall.h"

int get_dynsymbol_value(const char *path, char *);
Elf32_Shdr* get_section_byName(FILE *fp, int size, int ndx, char*);
int shsstroff, section_base;

/* -- Machine code -- */
unsigned char dlopen_code[] =
	push 		"\x02\x00\x00\x00"	// Second Argument
	push 		"\x00\x00\x00\x00"	// First Argument
	movl_ecx 	"\x00\x00\x00\x00"	// Set Function Pointer
	call_ecx						// Call dlopen
	add_esp 	"\x8"				// Clean stack
	trap;

/* -- Entry point!! -- */
int main(int argc, char **argv)
{
	int flag=0, ret, i=0, len;
	long dlopen_addr, ptr;
	char str[128];
	void *handle = NULL;
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

	// retrieve dlopen's file offset
	ret = get_dynsymbol_value(map[i]->mapname, "dlopen");
	// make virtual memory address
	dlopen_addr = map[i]->begin + ret;

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
	handle = execute_code(atoi(argv[1]), dlopen_code, len);

	if(handle)
		printf("[*] Shared object load sucessfully\n");
	else
		printf("[*] Shared object load failed\n");

	// release memory
	printf("[*] release temporary memory\n");
	remote_munmap(atoi(argv[1]), (void*)ptr, 8096);

	printf("[*] done\n");
	return 0;
}
	
/* -- Retrieve dlopen Symbol value -- */
int get_dynsymbol_value(const char *path, char *name)
{
	FILE *fp = fopen(path, "r");
	Elf32_Ehdr *ehdr = malloc(sizeof(Elf32_Ehdr));
	Elf32_Shdr *shdr = NULL;
	Elf32_Shdr *shstr = NULL;
	Elf32_Sym *sym = malloc(sizeof(Elf32_Sym));
	int i, symtab_ndx;
	char str[128];

	if(fp==NULL)
	{
		fprintf(stderr, "Can not open [%s]\n", path);
		exit(-1);
	}

	// read elf header to retrieve section information
	fread(ehdr, sizeof(Elf32_Ehdr), 1, fp);

	// calculate symbol string table section offset
	section_base = ehdr->e_shoff;
	shsstroff = ehdr->e_shoff + (ehdr->e_shentsize * ehdr->e_shstrndx);

	shdr = get_section_byName(fp, ehdr->e_shentsize, ehdr->e_shnum, ".dynsym");
	shstr = get_section_byName(fp, ehdr->e_shentsize, ehdr->e_shnum, ".dynstr");

	if(shdr!=NULL){
		symtab_ndx = shdr->sh_size / sizeof(Elf32_Sym);
		fseek(fp, shdr->sh_offset, SEEK_SET);

		for(i=0 ; i<symtab_ndx ; i++)
		{
			memset(str, 0, 128);
			fseek(fp, shdr->sh_offset + i*sizeof(Elf32_Sym), SEEK_SET);
			fread(sym, sizeof(Elf32_Sym), 1, fp);
			fseek(fp, shstr->sh_offset + sym->st_name, SEEK_SET);
			fgets(str, 128, fp);

			if(strstr(str, name))
				return sym->st_value;
		}
	}
		   	
	return 0;
}

/* -- Retrieve Section Pointer usign section name -- */
Elf32_Shdr* get_section_byName(FILE *fp, int size, int ndx, char* name)
{
	int i;
	long shstable;
	char str[128];

	Elf32_Shdr *shdr = malloc(sizeof(Elf32_Shdr));
	
	fseek(fp, shsstroff, SEEK_SET);
	fread(shdr, sizeof(Elf32_Shdr), 1, fp);
	shstable = shdr->sh_offset;

	fseek(fp, section_base, SEEK_SET);

	for(i=0 ; i<ndx ; i++){
		memset(str, 0, 128);
		fseek(fp, section_base + i*sizeof(Elf32_Shdr), SEEK_SET);
		fread(shdr, sizeof(Elf32_Shdr), 1, fp);

		fseek(fp, shstable + shdr->sh_name, SEEK_SET);
		fgets(str, 128, fp);

		if(!strcmp(str, name))
			return shdr;

	}
	return NULL;
}
