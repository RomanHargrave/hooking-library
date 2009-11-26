#include <stdio.h>

int main()
{
	printf("PID : %d\n",getpid());

	while(1)
	{
		printf("[-] I'm Alive \n");
		sleep(5);
	}
	return 0;
}
