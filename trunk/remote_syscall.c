/* -- remote syscall by binoopang [binoopang@gmail.com]---------------------------- *
 * This file contains the remote systemcall source code --------------------------- */

/* -- Remote munmap function -- */
int remote_munmap(pid_t pid, void *start, int size)
{
	int len, ret;

	set_reg(REG_EAX, __NR_munmap, machine_code);
	set_reg(REG_EBX, (unsigned int)start, machine_code);
	set_reg(REG_ECX, size, machine_code);

	len = get_codelen(machine_code);
	ret = (int)execute_code(pid, machine_code, len);

	return ret;
}

/* -- remote close function -- */
int remote_close(pid_t pid, int fd)
{
	int len, ret;

	set_reg(REG_EAX, __NR_close, machine_code);
	set_reg(REG_EBX, fd, machine_code);

	len = get_codelen(machine_code);
	ret = (int)execute_code(pid, machine_code, len);

	return ret;
}

int remote_exit(pid_t pid, int no)
{
	int len, ret;

	set_reg(REG_EAX, __NR_exit, machine_code);
	set_reg(REG_EBX, no, machine_code);

	len = get_codelen(machine_code);
	ret = (int)execute_exit_code(pid, machine_code, len);

	return ret;
}

int remote_fork(pid_t pid)
{
	int len, ret;

	set_reg(REG_EAX, __NR_fork, machine_code);

	len = get_codelen(machine_code);
	ret = (int)execute_code(pid, machine_code, len);

	return ret;
}

/* -- Remote open function -- */
int remote_open(pid_t pid, char *path, int flags)
{
	int len, ret;
	unsigned long ptr;

	ptr = (unsigned long)remote_mmap(pid, NULL, 128, PROT_READ|PROT_WRITE, 
			MAP_PRIVATE|MAP_ANONYMOUS,-1,0);

	if(ptr > 0)
	{
		ptrace_attach(pid);

		write_data(pid, ptr, path, strlen(path));
		ptrace_detach(pid);

		set_reg(REG_EAX, __NR_open, machine_code);
		set_reg(REG_EBX, (unsigned int)ptr, machine_code);
		set_reg(REG_ECX, flags, machine_code);

		len = get_codelen(machine_code);
		ret = execute_code(pid, machine_code, len);

		// release string memory space
		remote_munmap(pid, (void*)ptr, 128);
	}

	return ret;

}

int remote_write(pid_t pid, int fd, unsigned char* buf, int data_len)
{
	int len, ret;
	unsigned long ptr;

	ptr = (unsigned long)remote_mmap(pid, NULL, data_len+128, PROT_READ|PROT_WRITE, 
			MAP_PRIVATE|MAP_ANONYMOUS,-1,0);

	if(ptr > 0)
	{
		ptrace_attach(pid);
		write_data(pid, ptr, buf, data_len);
		ptrace_detach(pid);

		set_reg(REG_EAX, __NR_write, machine_code);
		set_reg(REG_EBX, fd, machine_code);
		set_reg(REG_ECX, (unsigned int)ptr, machine_code);
		set_reg(REG_EDX, data_len, machine_code);

		len = get_codelen(machine_code);
		ret = execute_code(pid, machine_code, len);

		// release string memory space
		remote_munmap(pid, (void*)ptr, data_len+128);
	}

	return ret;
}

int remote_read(pid_t pid, int fd, unsigned char* buf, int data_len)
{
	int len, ret;
	unsigned long ptr;

	ptr = (unsigned long)remote_mmap(pid, NULL, data_len+128, PROT_READ|PROT_WRITE, 
			MAP_PRIVATE|MAP_ANONYMOUS,-1,0);

	if(ptr > 0)
	{
		set_reg(REG_EAX, __NR_read, machine_code);
		set_reg(REG_EBX, fd, machine_code);
		set_reg(REG_ECX, (unsigned int)ptr, machine_code);
		set_reg(REG_EDX, data_len, machine_code);

		len = get_codelen(machine_code);
		ret = execute_code(pid, machine_code, len);

		// retrieve read data from target process
		ptrace_attach(pid);
		read_data(pid, ptr, buf, data_len);
		ptrace_detach(pid);

		printf("%s\n", buf);

		// release string memory space
		remote_munmap(pid, (void*)ptr, data_len+128);
	}

	return ret;
}
/* -- Remote mmap function -- */
void* remote_mmap(pid_t pid, void *start, size_t length, int prot, int flags, int fd, int offset)
{
	int len;
	void* ret;

	set_reg(REG_EAX, __NR_mmap2, machine_code);
	set_reg(REG_EBX, (unsigned int)start, machine_code);
	set_reg(REG_ECX, length, machine_code);
	set_reg(REG_EDX, prot, machine_code);
	set_reg(REG_ESI, flags, machine_code);
	set_reg(REG_EDI, fd, machine_code);
	set_reg(REG_EBP, offset, machine_code);

	len = get_codelen(machine_code);
	ret = (void*)execute_code(pid, machine_code, len);

	return ret;
}

/* -- set movl operand -- */
void set_reg(int reg, unsigned int val, char *code)
{
	switch(reg){
		case REG_EBX:
			memcpy(code+11, (void*)&val, 4);
			break;
		case REG_ECX:
			memcpy(code+16, (void*)&val, 4);
			break;
		case REG_EDX:
			memcpy(code+21, (void*)&val, 4);
			break;
		case REG_ESI:
			memcpy(code+26, (void*)&val, 4);
			break;
		case REG_EDI:
			memcpy(code+31, (void*)&val, 4);
			break;
		case REG_EBP:
			memcpy(code+36, (void*)&val, 4);
			break;
		case REG_EAX:
			memcpy(code+41, (void*)&val, 4);
			break;
	}
}

