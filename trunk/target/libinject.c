/* -- Dummy Shared Object by binooapng [binoopang@gmail.com] -- */

void __attribute__ ((constructor)) somain(void);
void __attribute__ ((destructor)) so_unload(void);

void somain(void)
{
	printf("\n[*] Shared object loaded sucessfully :)\n");
}

void so_unload(void)
{
	printf("\n[*] Shared object unloading... \n");
}
