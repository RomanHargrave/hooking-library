/* ------ This is remote system call demonstration program :) ------- */

#include <stdio.h>
#include "remote_syscall.c"

int main(int argc, char **argv)
{
	int fd;
	int ret;
	char *ptr = NULL;

	// 파일 매핑을 위하여 원격 프로세스가 파일을 열도록 유도
	fd = remote_open(atoi(argv[1]), "/tmp/binoopang", O_RDWR);
	if(fd>0)
		printf("[*] file open sucessfuly. FD : %d\n", fd);
	else{
		printf("[-] file not opened\n");
		exit(-1);
	}

	// 메모리 파일 매핑
	ptr = (char*)remote_mmap(atoi(argv[1]),						// PID
			(void*)NULL, 							// Address
			8096, 										// Segment size
			PROT_READ | PROT_WRITE | PROT_EXEC,			// Privileges
			MAP_PRIVATE,	// Flags
			fd,											// Fd
			0											// offset
			);

	printf("[*] Allocated at %p\n", ptr);

	// 매핑 해제
	ret = remote_munmap(atoi(argv[1]), (void*)ptr, 8096);

	if(ret==0)
		printf("[*] munmap sucessfully\n");
	else
		printf("[*] munmap failed\n");


	// 파일 닫기
	remote_close(atoi(argv[1]), fd);


	return 0;
}
