/*
	shellcodeexec - Script to execute in memory a sequence of opcodes
	Heavily rewritten by Vlatko Kosturjak, vlatko.kosturjak@gmail.com
	Heavily based on:
	Copyright (C) 2011  Bernardo Damele A. G.
	web: http://bernardodamele.blogspot.com
	email: bernardo.damele@gmail.com
	
	This source code is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.
	
	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
	
	You should have received a copy of the GNU Lesser General Public
	License along with this library; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

/* Microsoft Visual Studio have different way of specifying variable number of args */
#ifdef DEBUG
 #ifdef _MSC_VER
 #define DEBUG_PRINTF(fmt, ...) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
 #else
 #define DEBUG_PRINTF(fmt, args...) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, __LINE__, __FUNCTION__, ##args)
 #endif
#else
 #ifdef _MSC_VER
 #define DEBUG_PRINTF(fmt, ...)
 #else
 #define DEBUG_PRINTF(fmt, args...)
 #endif
#endif

#ifdef __MINGW32__
#define _WIN32_WINNT 0x502 
#endif

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
#include <windows.h>
DWORD WINAPI exec_payload(LPVOID lpParameter);
	#if defined(_WIN64)
	void __exec_payload(LPVOID);
	static DWORD64 handler_eip;
	#else
	static DWORD handler_eip;
	#endif
#else
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifndef CALL_FIRST
#define CALL_FIRST 1 
#endif

int sys_bineval(char *argv);

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Run:\n\t%s <alphanumeric-encoded shellcode>\n",argv[0]);
		exit(-1);
	}

	sys_bineval(argv[1]);

	exit(0);
}

int sys_bineval(char *argv)
{
	size_t len;

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
	int pID;
	char *code;
#else
	int *addr;
	size_t page_size;
	pid_t pID;
#endif

	len = (size_t)strlen(argv);

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
	// allocate a +rwx memory page
	DEBUG_PRINTF("Allocating RWX memory...\n");
	code = (char *) VirtualAlloc(NULL, len+1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// copy over the shellcode
	DEBUG_PRINTF("Copying shellcode\n");
	strncpy(code, argv, len);

	// execute it by ASM code defined in exec_payload function
	DEBUG_PRINTF("Executing shellcode\n");
	WaitForSingleObject(CreateThread(NULL, 0, exec_payload, code, 0, &pID), INFINITE);
#else
	DEBUG_PRINTF("Performing fork...\n");
	pID = fork();
	if(pID<0)
		return 1;

	if(pID==0)
	{
		page_size = (size_t)sysconf(_SC_PAGESIZE)-1;	// get page size
		page_size = (len+page_size) & ~(page_size);	// align to page boundary

		// mmap an +rwx memory page
		DEBUG_PRINTF("Mmaping memory page (+rwx)\n");
		addr = mmap(0, page_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANON, 0, 0);

		if (addr == MAP_FAILED)
			return 1;

		// copy over the shellcode
		DEBUG_PRINTF("Copying shellcode\n");
		strncpy((char *)addr, argv, len);

		// execute it
		DEBUG_PRINTF("Executing shellcode\n");
		((void (*)(void))addr)();
	}

	if(pID>0)
		waitpid(pID, 0, WNOHANG);
#endif

	return 0;
}

/* if windows */
#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32) 
/* if mingw */
#ifdef __MINGW32__ 
LONG WINAPI VectoredHandler (struct _EXCEPTION_POINTERS *ExceptionInfo) {
	PCONTEXT Context;
	Context = ExceptionInfo->ContextRecord;
	DEBUG_PRINTF("Exception occured. Entered into Exception Handler.\n");
#ifdef _AMD64_
	Context->Rip = handler_eip;
#else
	Context->Eip = handler_eip;
#endif    
	DEBUG_PRINTF("Returning from Exception handler\n");
	return EXCEPTION_CONTINUE_EXECUTION;
}

DWORD WINAPI exec_payload(LPVOID lpParameter)
{
	PVOID h;
	handler_eip = &&fail;

	DEBUG_PRINTF("Adding handler\n");
	h = AddVectoredExceptionHandler(CALL_FIRST,VectoredHandler);
	DEBUG_PRINTF("Executing payload\n");
#if defined(_WIN64)
	DEBUG_PRINTF("Executing payload64\n");
	__asm__ (
		"mov %0, %%rax\n"
		"call *%%rax\n"
		: // no output
		: "m"(lpParameter) // input
	);
#else
	DEBUG_PRINTF("Executing payload32\n");
	__asm__ (
		"mov %0, %%eax\n"
		"call *%%eax\n"
		: // no output
		: "m"(lpParameter) // input
	);
#endif
fail:
	DEBUG_PRINTF("Removing handler\n");
	RemoveVectoredExceptionHandler(h);

	return 0;
}
#else /* MINGW */

#if defined(_WIN64)

DWORD WINAPI exec_payload(LPVOID lpParameter)
{
	__try
	{
		__exec_payload(lpParameter);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return 0;
}
#elif defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
DWORD WINAPI exec_payload(LPVOID lpParameter)
{
	__try
	{
		__asm
		{
			mov eax, [lpParameter]
			call eax
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return 0;
}
#endif /* _WIN64 */
#endif /* __MINGW__ */
#endif /* if windows */
