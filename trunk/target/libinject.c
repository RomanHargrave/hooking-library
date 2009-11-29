void __attribute__ ((constructor)) somain(void);
void __attribute__ ((destructor)) so_unload(void);

void somain(void)
{
	printf("[*] Shared object loaded sucessfully :)\n");
}

void so_unload(void)
{
	printf("*] Shared object unloading... \n");
}
