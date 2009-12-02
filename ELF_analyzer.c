/* -- ELF Analyzer by binoopang [binoopang@gmail.com] ---------------- *
 * This file contains the ELF Analyzing functions.
 * If you want to retrieve ELF information, you can use it.        --- */

#include <stdio.h>
#include <stdlib.h>

/* -- proto types -- */
Elf32_Sym* get_dynsymbol(FILE *, char *);
Elf32_Sym* get_symbol(FILE* , char *);
Elf32_Shdr* get_section_byName(FILE *fp, char*);
Elf32_Ehdr* get_elf_header(FILE *fp);

/* -- Get ELF Header Pointer -- */
Elf32_Ehdr* get_elf_header(FILE* fp)
{
	Elf32_Ehdr* ehdr = malloc(sizeof(Elf32_Ehdr));
	fseek(fp, 0, SEEK_SET);
	fread(ehdr, sizeof(Elf32_Ehdr), 1, fp);

	return ehdr;
}

/* -- Get Symbol Structure pointer -- */
Elf32_Sym* get_dynsymbol(FILE *fp, char *name)
{
	Elf32_Ehdr *ehdr = NULL;
	Elf32_Shdr *shdr = NULL;
	Elf32_Shdr *shstr = NULL;
	Elf32_Sym *sym = malloc(sizeof(Elf32_Sym));
	int i, symtab_ndx;
	char str[128];

	// read elf header to retrieve section information
	ehdr = get_elf_header(fp);

	shdr = get_section_byName(fp, ".dynsym");
	shstr = get_section_byName(fp, ".dynstr");

	free(ehdr);

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
				return sym;
		}
	}
	return NULL;
}

/* -- Get Symbol Structure pointer -- */
Elf32_Sym* get_symbol(FILE *fp, char *name)
{
	Elf32_Ehdr *ehdr = NULL;
	Elf32_Shdr *shdr = NULL;
	Elf32_Shdr *shstr = NULL;
	Elf32_Sym *sym = malloc(sizeof(Elf32_Sym));
	int i, symtab_ndx;
	char str[128];


	// read elf header to retrieve section information
	ehdr = get_elf_header(fp);

	shdr = get_section_byName(fp, ".symtab");
	shstr = get_section_byName(fp, ".strtab");

	free(ehdr);

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
				return sym;
		}
	}
	return NULL;
}
/* -- Retrieve Section Pointer usign section name -- */
Elf32_Shdr* get_section_byName(FILE *fp, char* name)
{
	int i, size, ndx;
	int shsstroff, section_base;
	int shstable;
	char str[128];
	Elf32_Ehdr *ehdr = get_elf_header(fp);
	Elf32_Shdr *shdr = malloc(sizeof(Elf32_Shdr));

	// calculate symbol string table section offset
	section_base = ehdr->e_shoff;
	shsstroff = ehdr->e_shoff + (ehdr->e_shentsize * ehdr->e_shstrndx);
	size = ehdr->e_shentsize;
	ndx = ehdr->e_shnum;
	free(ehdr);

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
