/* ------ This is remote system call demonstration program :) ------- */

#include <stdio.h>
#include "remote_syscall.h"

char *string = "[*] I am remote message !!\n";

int main(int argc, char **argv)
{
	int fd;
	int ret, i=0;
	char *ptr = NULL;
	char buffer[128] = {0,};

	PMAP_INFO *map = get_map_info(atoi(argv[1]));

	while(map[i]!=NULL)
	{
		printf("[*] 0x%lx - 0x%lx %s %s\n",
				map[i]->begin, map[i]->end, 
				map[i]->perm, map[i]->mapname);
		free(map[i]);
		i++;
	}

	// Open file to mapping
	fd = remote_open(atoi(argv[1]), // PID
			"/tmp/binoopang", 		// Target File
			O_RDWR);				// Flag
	if(fd>0)
		printf("[*] file open sucessfuly. FD : %d\n", fd);
	else{
		printf("[-] file not opened\n");
		exit(-1);
	}

	// memory mapping
	ptr = (char*)remote_mmap(atoi(argv[1]),	// PID
			(void*)NULL, 					// Address
			8096, 							// Segment size
			PROT_READ | PROT_WRITE | PROT_EXEC,	// Privileges
			MAP_PRIVATE,						// Flags
			fd,									// Fd
			0									// offset
			);

	printf("[*] Allocated at %p\n", ptr);

	// release mapped memory
	ret = remote_munmap(atoi(argv[1]), 	// PID
			(void*)ptr, 				// Start Address
			8096);						// Size

	if(ret==0)
		printf("[*] munmap sucessfully\n");
	else
		printf("[*] munmap failed\n");

	// write to file
	ret = remote_write(atoi(argv[1]), 	// PID
			1, 						// FD
			string, 					// Input Buffer
			strlen(string));			// length
	printf("[*] write : %d\n", ret);

	// close file
	remote_close(atoi(argv[1]), fd);
	remote_exit(atoi(argv[1]), 0);
	return 0;
}
