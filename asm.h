/* -- Assembly Codes by binoopang [binoopang@gmail.com]------------ *
 * This file contains the Machine code defines. 
 * This define is used for more readable                      ----- */

#ifndef ASM_H
#define ASM_H 


#ifdef __i386__
/* -- 32bit system -- */
#define INIT_STUB 	"\x55\x53\x56\x57\x31\xd2\x31\xf6\x31\xc9" 	// PUSH & XOR
#define FINI_STUB 	"\x5f\x5e\x5b\x5d\xcc"		 				// POP
#define syscall		"\xcd\x80"
#define trap		"\xcc"
#define add_esp		"\x83\xc4"	// operand 1byte
#define call_eax	"\xff\xd0"
#define call_ebx	"\xff\xd3"
#define call_ecx	"\xff\xd1"
#define call_edx	"\xff\xd2"
#define call_esi	"\xff\xd6"
#define call_edi	"\xff\xd7"
#define call_ebp	"\xff\xd5"
#define movl_eax 	"\xb8"		// operand 4byte
#define movl_ebx 	"\xbb"
#define movl_ecx 	"\xb9"
#define movl_edx 	"\xba"
#define movl_esi 	"\xbe"
#define movl_edi 	"\xbf"
#define movl_ebp 	"\xbd"
#define push		"\x68"		// operand 4byte
#define nop			"\x90"
#else
/* -- 64bit system -- *
 * -- NOT YET T_T --- */
#endif

#endif
