/* -- Assembly Codes ---------------------------------------------- */

#ifndef ASM_H
#define ASM_H 

/* -- x86 Assembly code -- */
#define INIT_STUB 	"\x55\x53\x56\x57\x31\xd2\x31\xf6\x31\xc9" 	// PUSH & XOR
#define FINI_STUB 	"\x5f\x5e\x5b\x5d\xcc"		 				// POP
#define syscall		"\xcd\x80"
#define trap		"\xcc"
#define add_esp		"\x83\xc4"
#define call_ecx	"\xff\xd1"
#define movl_eax 	"\xb8"
#define movl_ebx 	"\xbb"
#define movl_ecx 	"\xb9"
#define movl_edx 	"\xba"
#define movl_esi 	"\xbe"
#define movl_edi 	"\xbf"
#define movl_ebp 	"\xbd"
#define push		"\x68"
#define nop			"\x90"

#endif
