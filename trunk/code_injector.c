/* -- ELF Code Injector by binoopang [binoopang@gmail.com]----------------------- */

#ifndef CODE_INJECTOR_C
#define CODE_INJECTOR_C 1

/* -- remote injection help functions -- */
void restore_code(int pid, unsigned long base_address, long original_code[], struct user_regs_struct *regs, int);
unsigned int execute_code(int pid, unsigned char code[], int);
int get_codelen(unsigned char code[]);
unsigned long get_map_info(int pid, char *);

/* -- ptrace help functions -- */
void ptrace_detach(int pid);
void ptrace_cont(int pid);
void ptrace_setregs(int pid, struct user_regs_struct*);
void ptrace_getregs(int pid, struct user_regs_struct*);
void ptrace_attach(int pid);
char *read_str(int pid, unsigned long addr, int len);
void * read_data(int pid, unsigned long addr, void *vptr, int len);
void write_data(int pid, unsigned long target_address, unsigned char code[], int len);


/* -- 코드 복구 함수 -- */
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

/* -- 코드 주입용 함수 -- */
unsigned int execute_code(int pid, unsigned char code[], int CODE_LENGTH)
{
	long reg_eip;
	unsigned int ret;
	unsigned char original_code[128];
	int i, j; 
	struct user_regs_struct regs;
	struct user_regs_struct regs_ret;
	unsigned int base_address = 0x8048000;

	/* -- 타깃 프로세스 잡기 -- */
	ptrace_attach(pid);

	/* -- 타깃 프로세스의 EIP 레지스터 값 저장 -- */
	ptrace_getregs(pid, &regs);
	reg_eip = regs.eip;

	/* -- eip 주소를 바꿔서 내가 입력한 코드 실행 -- */
	regs.eip = base_address+2;
	ptrace_setregs(pid, &regs);

	/* -- 원래 코드(?) 백업 -- */
	for(i=0, j=0 ; i<CODE_LENGTH/4 ; i++, j+=4)
	{
		original_code[i] = ptrace(PTRACE_PEEKDATA, pid, 
										(caddr_t)base_address+j, NULL);
#ifdef __print__
		printf("[-] OLD CODE : 0x%lx : %lx\n",
										base_address+j, original_code[i]);
#endif
	}

	/* -- 새로운 코드 삽입 -- */
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

	/* -- 삽입한 코드 실행 -- */
	ptrace_cont(pid);

	/* -- 코드 실행 후 리턴값 가져오기 -- */
	ptrace_getregs(pid, &regs_ret);
	ret = (unsigned int)regs_ret.eax;

	/* -- 원래 EIP 복구 -- */
	regs.eip=reg_eip;

	/* -- 원래 코드로 복구 -- */
	restore_code(pid, base_address, original_code, &regs, CODE_LENGTH);

	/* -- 프로세스 놓아주기 -- */
	ptrace_detach(pid);

	return ret;
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

unsigned long get_map_info(int pid, char *name)
{
	char fname[PATH_MAX];
	unsigned long writable=0, total=0, shared=0;
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

		if(fgets(buf, sizeof(buf), f) == 0)
			break;

		mapname[0] = '\0';
		sscanf(buf, "%lx-%lx %4s %lx %5s %ld %s", &begin, &end, perm,
				&foo, dev, &inode, mapname);
		
		if(strstr(perm, name) && !strstr(mapname, "vdso"))
			return begin;
	}
	return 0;
}

int get_codelen(unsigned char code[])
{
	int i=0;
	while(code[i] != 0xcc)
		i++;

	return i+1;
}

// 대상 프로세스의 특정주소에서 데이터 읽어들이기
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

// 문자열 읽어 들이기
char *read_str(int pid, unsigned long addr, int len)
{
	char *ret = calloc(32, sizeof(char));
	read_data(pid, addr, ret, len);
	return ret;
}


// 특정 프로세스 붙이기
void ptrace_attach(int pid)
{
  if((ptrace(PTRACE_ATTACH , pid , NULL , NULL)) < 0) {
   perror("ptrace_attach");
   exit(-1);
  }

  waitpid(pid , NULL , WUNTRACED);
}

// 레지스터 정보 가져오기
void ptrace_getregs(int pid, struct user_regs_struct *regs)
{
  if((ptrace(PTRACE_GETREGS, pid, NULL, regs)) < 0)
  {
          perror("ptrace_getregs");
          exit(-1);
  }
}

// 레지스터 설정하기
void ptrace_setregs(int pid, struct user_regs_struct *regs)
{
  if((ptrace(PTRACE_SETREGS, pid, NULL, regs)) < 0)
  {
          perror("ptrace_getregs");
          exit(-1);
  }
}

// 계속 실행하기
void ptrace_cont(int pid)
{
  int s;
  if((ptrace(PTRACE_CONT , pid , NULL , NULL)) < 0) {
   perror("ptrace_cont");
   exit(-1);
  }

  while (!WIFSTOPPED(s)) waitpid(pid , &s , WNOHANG);
}


// 프로세스 놓아주기
void ptrace_detach(int pid)
{
  if(ptrace(PTRACE_DETACH, pid , NULL , NULL) < 0) {
   perror("ptrace_detach");
   exit(-1);
  }
}

#endif
