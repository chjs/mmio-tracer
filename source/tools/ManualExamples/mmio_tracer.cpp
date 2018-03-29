/*BEGIN_LEGAL 
  Intel Open Source License 

  Copyright (c) 2002-2017 Intel Corporation. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "pin.H"

#define TRUE		1
#define FALSE		0
#define PAGE_SHIFT	12
#define PAGE_MASK	(~(PAGE_SIZE - 1))
#define MAP_DEBUG	0x80000

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
		"o", "mmio_trace.out", "specify output file name");

//==============================================================
//  Analysis Routines
//==============================================================
// Note:  threadid+1 is used as an argument to the PIN_GetLock()
//        routine as a debugging aid.  This is the value that
//        the lock is set to, so it must be non-zero.

// lock serializes access to the output file.
FILE * out;
PIN_LOCK pinLock;

typedef enum callType {
	SYSTEMCALL = 100,
	LIBCALL,
} CallType;

typedef enum syscallType {
	S_NONE = 0,
	S_MMAP,
	S_MUNMAP,
	S_MSYNC,
	S_MADVISE
} SyscallType;

typedef enum libcallType {
	L_NONE = 10,
	L_MEMCPY,
	L_MEMSET
} LibcallType;

typedef struct threadNode {
	THREADID tid;
	SyscallType sType;
	LibcallType lType;
	void *syscallArgs;
	void *libcallArgs;
	struct threadNode *next;
} ThreadNode;

ThreadNode *threadNodeHead = NULL;
ThreadNode *threadNodeTail = NULL;

typedef struct memNode {
	char filename[128];
	unsigned long start;
	unsigned long end;
	unsigned long length;
	unsigned long nrpages;
	struct memNode *next;
} MemNode;

MemNode *memNodeHead = NULL;
MemNode *memNodeTail = NULL;

typedef struct mmapArgs {
	char filename[128];
	unsigned long addr;
	size_t length;
	int prot;
	int flags;
	int fd;
	off_t offset;
} MmapArgs;

typedef struct munmapArgs {
	char filename[128];
	unsigned long addr;
	size_t length;
} MunmapArgs;

typedef struct msyncArgs {
	char filename[128];
	unsigned long addr;
	size_t length;
	int flags;
} MsyncArgs;

typedef struct memcpyArgs {
	char filename[128];
	unsigned long dst;
	unsigned long src;
	size_t length;
} MemcpyArgs;

char *findMemNode(unsigned long addr, unsigned long *pgoff, THREADID tid) {
	MemNode *curr = NULL;

	curr = memNodeHead;
	while (curr) {
		if ((curr->start <= addr) && (addr < curr->end)) {
			*pgoff = ((addr & PAGE_MASK) - curr->start) >> PAGE_SHIFT;
			return curr->filename;
		}
		curr = curr->next;
	}
	return NULL;
}

int insertMemNode(char *filename, unsigned long start, unsigned long end, unsigned long length,
		unsigned long nrpages, THREADID tid) {
	MemNode *newNode = (MemNode *)malloc(sizeof(MemNode));

	if (newNode == NULL) {
		fprintf(out, "[%d] %s: malloc() failed. (ERROR)\n", tid, __func__);
		fflush(out);
		return FALSE;
	}
	strcpy(newNode->filename, filename);
	newNode->start = start;
	newNode->end = end;
	newNode->length = length;
	newNode->nrpages = nrpages;

	if (memNodeHead == NULL)
		memNodeHead = newNode;
	if (memNodeTail != NULL)
		memNodeTail->next = newNode;
	memNodeTail = newNode;
	//fprintf(out, "[%d] %s: A memNode was inserted into the memNode list.\n", tid, __func__);
	//fflush(out);
	return TRUE;
}

int insertThreadNode(THREADID tid) {
	ThreadNode *newNode = (ThreadNode *)malloc(sizeof(ThreadNode));

	if (newNode == NULL) {
		fprintf(out, "[%d] %s: malloc() failed. (ERROR)\n", tid, __func__);
		fflush(out);
		return FALSE;
	}
	newNode->tid = tid;
	newNode->sType = S_NONE;
	newNode->lType = L_NONE;
	newNode->syscallArgs = NULL;
	newNode->libcallArgs = NULL;
	newNode->next = NULL;

	if (threadNodeHead == NULL)
		threadNodeHead = newNode;
	if (threadNodeTail != NULL)
		threadNodeTail->next = newNode;
	threadNodeTail = newNode;
	//fprintf(out, "[%d] %s: A threadNode was inserted into the threadNode list.\n", tid, __func__);
	//fflush(out);
	return TRUE;
}

int deleteMemNode(unsigned long start, unsigned long length, THREADID tid) {
	MemNode *prev = NULL;
	MemNode *curr = NULL;

	curr = memNodeHead;
	while (curr) {
		if ((curr->start == start) && (curr->length == length)) {
			if (prev != NULL)
				prev->next = curr->next;
			else
				memNodeHead = curr->next;
			if (curr->next == NULL)
				memNodeTail = prev;
			free(curr);
			//fprintf(out, "[%d] %s: A memNode was deleted.\n", tid, __func__);
			//fflush(out);
			return TRUE;
		}
		prev = curr;
		curr = curr->next;
	}
	fprintf(out, "[%d] %s: This memNode can not be deleted. (ERROR)\n", tid, __func__);
	fflush(out);
	return FALSE;
}

int deleteThreadNode(THREADID tid) {
	ThreadNode *prev = NULL;
	ThreadNode *curr = NULL;

	curr = threadNodeHead;
	while (curr) {
		if (curr->tid == tid) {
			if (prev != NULL)
				prev->next = curr->next;
			else
				threadNodeHead = curr->next;
			if (curr->next == NULL)
				threadNodeTail = prev;
			free(curr);
			//fprintf(out, "[%d] %s: A threadNode was deleted.\n", tid, __func__);
			//fflush(out);
			return TRUE;
		}
		prev = curr;
		curr = curr->next;
	}
	fprintf(out, "[%d] %s: This threadNode can not be deleted. (ERROR)\n", tid, __func__);
	fflush(out);
	return FALSE;
}

int putSyscallArgs(THREADID tid, void *args, SyscallType type) {
	ThreadNode *curr = threadNodeHead;

	while (curr) {
		if (curr->tid == tid) {
			if (curr->syscallArgs != NULL) {
				fprintf(out, "%d, %s: syscallArgs already exists. (ERROR)\n",
						tid, __func__);
				fflush(out);
				exit(EXIT_FAILURE);
			}
			curr->syscallArgs = args;
			curr->sType = type;
			return TRUE;
		}
		curr = curr->next;
	}
	fprintf(out, "%d, %s: THREADID is not exist. (ERROR)\n", tid, __func__);
	fflush(out);
	return FALSE;
}

int putLibcallArgs(THREADID tid, void *args, LibcallType type) {
	ThreadNode *curr = threadNodeHead;

	while (curr) {
		if (curr->tid == tid) {
			if (curr->libcallArgs != NULL) {
				fprintf(out, "%d, %s: libcallArgs already exists. (ERROR)\n",
						tid, __func__);
				fflush(out);
				exit(EXIT_FAILURE);
			}
			curr->libcallArgs = args;
			curr->lType = type;
			return TRUE;
		}
		curr = curr->next;
	}
	fprintf(out, "%d, %s: THREADID is not exist. (ERROR)\n", tid, __func__);
	fflush(out);
	return FALSE;
}

void *getSyscallArgs(THREADID tid, SyscallType *type) {
	ThreadNode *curr = threadNodeHead;
	void *args = NULL;

	while (curr) {
		if (curr->tid == tid) {
			/*
			if (curr->syscallArgs == NULL) {
				fprintf(out, "%d, %s: There is no syscallArgs. (ERROR)\n",
						tid, __func__);
				fflush(out);
				exit(EXIT_FAILURE);
			}
			*/
			args = curr->syscallArgs;
			*type = curr->sType;
			curr->syscallArgs = NULL;
			return args;
		}
		curr = curr->next;
	}
	fprintf(out, "%d, %s: THREADID is not exist. (ERROR)\n", tid, __func__);
	fflush(out);
	return NULL;
}

void *getLibcallArgs(THREADID tid, LibcallType *type) {
	ThreadNode *curr = threadNodeHead;
	void *args = NULL;

	while (curr) {
		if (curr->tid == tid) {
			/*
			if (curr->libcallArgs == NULL) {
				fprintf(out, "%d, %s: There is no libcallArgs. (ERROR)\n",
						tid, __func__);
				fflush(out);
				exit(EXIT_FAILURE);
			}
			*/
			args = curr->libcallArgs;
			*type = curr->lType;
			curr->libcallArgs = NULL;
			return args;
		}
		curr = curr->next;
	}
	fprintf(out, "%d, %s: THREADID is not exist. (ERROR)\n", tid, __func__);
	fflush(out);
	return NULL;
}

// This routine is executed every time a thread is created.
VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
	PIN_GetLock(&pinLock, tid+1);
	fprintf(out, "%d, thread-begin\n",tid);
	fflush(out);
	PIN_ReleaseLock(&pinLock);
	insertThreadNode(tid);
}

// This routine is executed every time a thread is destroyed.
VOID ThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 code, VOID *v) {
	PIN_GetLock(&pinLock, tid+1);
	fprintf(out, "%d, thread-end\n",tid);
	fflush(out);
	PIN_ReleaseLock(&pinLock);
	deleteThreadNode(tid);
}

// This routine is executed each time mmap() is called.
VOID BeforeMmap(THREADID tid,
		unsigned long addr, size_t length, int prot, int flags, int fd, off_t offset) {
	MmapArgs *args;
	int pid;
	char *path, *filename;
	ssize_t result;

	/* only memory mapped files are traced. */
	if (fd <= 0)
		return;

	/* trace only when mmap is called with the MAP_DEBUG flag. */
	if (!(flags & MAP_DEBUG))
		return;

	/* get filename */
	pid = PIN_GetPid();
	path = (char *)malloc(128);
	filename = (char *)malloc(128);
	strcpy(path, "/proc/");
	sprintf(&path[strlen(path)], "%d", pid);
	strcat(path, "/fd/");
	sprintf(&path[strlen(path)], "%d", fd);

	result = readlink(path, filename, 128);

	if (result < 0) {
		PIN_GetLock(&pinLock, tid+1);
		fprintf(out, "[%d] %s: readlink() failed. path=%s, filename=%s, fd=%d (ERROR)\n",
				tid, __func__, path, filename, fd);
		fflush(out);
		PIN_ReleaseLock(&pinLock);
		exit(EXIT_FAILURE);
	}

	args = (MmapArgs *)malloc(sizeof(MmapArgs));
	if (args == NULL) {
		PIN_GetLock(&pinLock, tid+1);
		fprintf(out, "[%d] %s: malloc() failed (ERROR)\n", tid, __func__);
		fflush(out);
		PIN_ReleaseLock(&pinLock);
		exit(EXIT_FAILURE);
	}

	PIN_GetLock(&pinLock, tid+1);
	fprintf(out, "%d, mmap-call, 0x%lx, %lu, 0x%x, 0x%x, %s, %ld\n",
			tid, addr, length, prot, flags, filename, offset);
	fflush(out);
	PIN_ReleaseLock(&pinLock);

	strcpy(args->filename, filename);
	args->addr = addr;
	args->length = length;
	args->prot = prot;
	args->flags = flags;
	args->fd = fd;
	args->offset = offset;

	PIN_GetLock(&pinLock, tid+1);
	putSyscallArgs(tid, (void *)args, S_MMAP);
	PIN_ReleaseLock(&pinLock);
}

VOID AfterMmap(THREADID tid, MmapArgs *args, unsigned long ret) {
	unsigned long start, end, nrpages;
	int result;

	start = ret;
	end = start + args->length;
	nrpages = args->length >> PAGE_SHIFT;

	PIN_GetLock(&pinLock, tid+1);
	result = insertMemNode(args->filename, start, end, args->length, nrpages, tid);
	PIN_ReleaseLock(&pinLock);

	if (result) {
		PIN_GetLock(&pinLock, tid+1);
		fprintf(out, "%d, mmap-return, 0x%lx\n", tid, ret);
		fflush(out);
		PIN_ReleaseLock(&pinLock);
	}
	else {
		PIN_GetLock(&pinLock, tid+1);
		fprintf(out, "%d, %s: insertMemNode failed. (ERROR)\n", tid, __func__);
		fflush(out);
		PIN_ReleaseLock(&pinLock);
		exit(EXIT_FAILURE);
	}

	free(args);
}

// This routine is executed each time munmap() is called.
VOID BeforeMunmap(THREADID tid, unsigned long addr, size_t length) {
	MunmapArgs *args;
	char *filename;
	unsigned long pgoff;

	PIN_GetLock(&pinLock, tid+1);
	filename = findMemNode(addr, &pgoff, tid);
	PIN_ReleaseLock(&pinLock);

	if (filename == NULL)
		return;

	args = (MunmapArgs *)malloc(sizeof(MunmapArgs));
	if (args == NULL) {
		PIN_GetLock(&pinLock, tid+1);
		fprintf(out, "%d, %s: malloc() failed (ERROR)\n", tid, __func__);
		fflush(out);
		PIN_ReleaseLock(&pinLock);
		exit(EXIT_FAILURE);
	}

	strcpy(args->filename, filename);
	args->addr = addr;
	args->length = length;

	PIN_GetLock(&pinLock, tid+1);
	putSyscallArgs(tid, (void *)args, S_MUNMAP);
	fprintf(out, "%d, munmap-call, 0x%lx, %lu\n", tid, addr, length);
	fflush(out);
	PIN_ReleaseLock(&pinLock);
}

VOID AfterMunmap(THREADID tid, MunmapArgs *args, int ret) {
	int result;

	PIN_GetLock(&pinLock, tid+1);
	result = deleteMemNode(args->addr, args->length, tid);
	PIN_ReleaseLock(&pinLock);

	if (result) {
		PIN_GetLock(&pinLock, tid+1);
		fprintf(out, "%d, munmap-return, %d\n", tid, ret);
		fflush(out);
		PIN_ReleaseLock(&pinLock);
	}
	else {
		PIN_GetLock(&pinLock, tid+1);
		fprintf(out, "%d, %s: deleteMemNode failed. (ERROR)\n", tid, __func__);
		fflush(out);
		PIN_ReleaseLock(&pinLock);
		exit(EXIT_FAILURE);
	}
	free(args);
}

// This routine is executed each time msync() is called.
VOID BeforeMsync(THREADID tid, unsigned long addr, size_t length, int flags) {
	MsyncArgs *args;
	char *filename;
	unsigned long pgoff;

	PIN_GetLock(&pinLock, tid+1);
	filename = findMemNode(addr, &pgoff, tid);
	PIN_ReleaseLock(&pinLock);

	if (filename == NULL)
		return;

	args = (MsyncArgs *)malloc(sizeof(MsyncArgs));
	if (args == NULL) {
		PIN_GetLock(&pinLock, tid+1);
		fprintf(out, "[%d] %s: malloc() failed (ERROR)\n", tid, __func__);
		fflush(out);
		PIN_ReleaseLock(&pinLock);
		exit(EXIT_FAILURE);
	}

	strcpy(args->filename, filename);
	args->addr = addr;
	args->length = length;
	args->flags = flags;

	PIN_GetLock(&pinLock, tid+1);
	fprintf(out, "%d, msync-call, 0x%lx, %lu, %s\n",
			tid, addr, length, filename);
	fflush(out);
	putSyscallArgs(tid, (void *)args, S_MSYNC);
	PIN_ReleaseLock(&pinLock);
}

VOID AfterMsync(THREADID tid, MsyncArgs *args, int ret) {
	PIN_GetLock(&pinLock, tid+1);
	fprintf(out, "%d, msync-return, %d\n", tid, ret);
	fflush(out);
	PIN_ReleaseLock(&pinLock);
	free(args);
}

VOID SyscallEntry(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	int number = (int)PIN_GetSyscallNumber(ctxt, std);

	if (number == __NR_mmap) {
		BeforeMmap(tid, (unsigned long)PIN_GetSyscallArgument(ctxt, std, 0),
				(size_t)PIN_GetSyscallArgument(ctxt, std, 1),
				(int)PIN_GetSyscallArgument(ctxt, std, 2),
				(int)PIN_GetSyscallArgument(ctxt, std, 3),
				(int)PIN_GetSyscallArgument(ctxt, std, 4),
				(off_t)PIN_GetSyscallArgument(ctxt, std, 5));
	}
	else if (number == __NR_munmap) {
		BeforeMunmap(tid, (unsigned long)PIN_GetSyscallArgument(ctxt, std, 0),
				(size_t)PIN_GetSyscallArgument(ctxt, std, 1));
	}
	else if (number == __NR_msync) {
		BeforeMsync(tid, (unsigned long)PIN_GetSyscallArgument(ctxt, std, 0),
				(size_t)PIN_GetSyscallArgument(ctxt, std, 1),
				(int)PIN_GetSyscallArgument(ctxt, std, 2));
	}
		
}

VOID SyscallExit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	void *args;
	SyscallType type;

	PIN_GetLock(&pinLock, tid+1);
	args = getSyscallArgs(tid, &type);
	PIN_ReleaseLock(&pinLock);

	if (args == NULL)
		return;

	switch (type) {
		case S_MMAP:
			AfterMmap(tid, (MmapArgs *)args, (unsigned long)PIN_GetSyscallReturn(ctxt, std));
			break;
		case S_MUNMAP:
			AfterMunmap(tid, (MunmapArgs *)args, (int)PIN_GetSyscallReturn(ctxt, std));
			break;
		case S_MSYNC:
			AfterMsync(tid, (MsyncArgs *)args, (int)PIN_GetSyscallReturn(ctxt, std));
			break;
		default:
			PIN_GetLock(&pinLock, tid+1);
			fprintf(out, "%d, %s: The args type is incorrect. (ERROR)\n", tid, __func__);
			fflush(out);
			PIN_ReleaseLock(&pinLock);
			exit(EXIT_FAILURE);
	}
}

VOID BeforeMemcpy(ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, THREADID tid)
{
	MemcpyArgs *args;
	unsigned long pgoff;
	char *filename;

	unsigned long dst = (unsigned long)arg0;
	unsigned long src = (unsigned long)arg1;
	size_t length = (size_t)arg2;

	PIN_GetLock(&pinLock, tid+1);
	filename = findMemNode(dst, &pgoff, tid);
	PIN_ReleaseLock(&pinLock);

	if (filename == NULL)
		return;

	args = (MemcpyArgs *)malloc(sizeof(MemcpyArgs));
	if (args == NULL) {
		PIN_GetLock(&pinLock, tid+1);
		fprintf(out, "%d, %s: malloc() failed (ERROR)\n", tid, __func__);
		fflush(out);
		PIN_ReleaseLock(&pinLock);
		exit(EXIT_FAILURE);
	}

	strcpy(args->filename, filename);
	args->dst = dst;
	args->src = src;
	args->length = length;

	PIN_GetLock(&pinLock, tid+1);
	putLibcallArgs(tid, (void *)args, L_MEMCPY);
	fprintf(out, "%d, memcpy-call, 0x%lx, 0x%lx, %lu, %s\n", tid, dst, src, length, filename);
	fflush(out);
	PIN_ReleaseLock(&pinLock);
}

VOID AfterMemcpy(ADDRINT ret, THREADID tid) {
	MemcpyArgs *args;
	LibcallType type;

	PIN_GetLock(&pinLock, tid+1);
	args = (MemcpyArgs *)getLibcallArgs(tid, &type);
	PIN_ReleaseLock(&pinLock);

	if (args == NULL)
		return;

	if (type == L_MEMCPY) {
		PIN_GetLock(&pinLock, tid+1);
		fprintf(out, "%d, memcpy-return, 0x%lx\n", tid, (unsigned long)ret);
		fflush(out);
		PIN_ReleaseLock(&pinLock);
	}
	else {
		PIN_GetLock(&pinLock, tid+1);
		fprintf(out, "%d, %s: LibcallType is wrong.\n", tid, __func__);
		fflush(out);
		PIN_ReleaseLock(&pinLock);
		exit(EXIT_FAILURE);
	}
}

// Print a memory read record
VOID RecordMemRead(VOID * ip, VOID * addr, THREADID tid)
{
	unsigned long pgoff;
	char *filename;
	unsigned long ip_addr = (unsigned long)ip;
	unsigned long mem_addr = (unsigned long)addr;

	PIN_GetLock(&pinLock, tid+1);
	filename = findMemNode(mem_addr, &pgoff, tid);
	PIN_ReleaseLock(&pinLock);

	if (filename == NULL)
		return;

	PIN_GetLock(&pinLock, tid+1);
	fprintf(out, "%d, READ, 0x%lx, 0x%lx, %lu, %s\n", tid, ip_addr, mem_addr, pgoff, filename);
	fflush(out);
	PIN_ReleaseLock(&pinLock);
}

// Print a memory write record
VOID RecordMemWrite(VOID * ip, VOID * addr, THREADID tid)
{
	unsigned long pgoff;
	char *filename;
	unsigned long ip_addr = (unsigned long)ip;
	unsigned long mem_addr = (unsigned long)addr;

	PIN_GetLock(&pinLock, tid+1);
	filename = findMemNode(mem_addr, &pgoff, tid);
	PIN_ReleaseLock(&pinLock);

	if (filename == NULL)
		return;

	PIN_GetLock(&pinLock, tid+1);
	fprintf(out, "%d, WRITE, 0x%lx, 0x%lx, %lu, %s\n", tid, ip_addr, mem_addr, pgoff, filename);
	fflush(out);
	PIN_ReleaseLock(&pinLock);
}

// Capture the return address of the ifunc which is the address of the actual memcpy
VOID * IfuncMemcpyWrapper(CONTEXT * context, AFUNPTR orgFuncptr, THREADID tid)
{
	VOID * ret;

	PIN_CallApplicationFunction( context, PIN_ThreadId(),
			CALLINGSTD_DEFAULT, orgFuncptr,
			NULL, PIN_PARG(void *), &ret,
			PIN_PARG_END() );
	
	//actual_memcpy_add[ifunc_index++] = (ADDRINT)ret;
	printf("%d, ifunc_memcpy() return 0x%lx\n", tid, (unsigned long)ret);
	return ret;
}

#if 0
VOID Trace(TRACE trace, VOID *v) {
	int i;

	for (i=0; i<ifunc_index; i++) {
		if (TRACE_Address(trace) == actual_memcpy_add[i]) {
			TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)BeforeMemcpy,
					IARG_ADDRINT, "memcpy(i-func)",
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
					IARG_THREAD_ID,
					IARG_END);

		}
	}
}
#endif

VOID Routine( IMG img, RTN rtn, void * v)
{
	// In some libc implementations, memcpy, memmove  symbols have the same address.
	// In this case, since Pin only creates one RTN per start address, the RTN name
	// will be either memcpy, memmove.
	bool isMemmove = strcmp(RTN_Name(rtn).c_str(),"memmove")==0 ;
	bool isMemcpy = strcmp(RTN_Name(rtn).c_str(),"memcpy")==0 ;

	if (isMemmove || isMemcpy)
	{
		if (SYM_IFuncResolver(RTN_Sym(rtn)))
		{
			PROTO proto_ifunc_memcpy = PROTO_Allocate( PIN_PARG(void *), CALLINGSTD_DEFAULT,
					"memcpy", PIN_PARG_END() );

			RTN_ReplaceSignature(rtn, AFUNPTR( IfuncMemcpyWrapper ),
					IARG_PROTOTYPE, proto_ifunc_memcpy,
					IARG_CONTEXT,
					IARG_ORIG_FUNCPTR,
					IARG_THREAD_ID,
					IARG_END);
		}
		else
		{
			RTN_Open(rtn);

			// Instrument memcpy() to print the input argument value and the return value.
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)BeforeMemcpy,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
					IARG_THREAD_ID,
					IARG_END);

			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AfterMemcpy,
					IARG_FUNCRET_EXITPOINT_VALUE,
					IARG_THREAD_ID,
					IARG_END);

			RTN_Close(rtn);
		}
	}
}

VOID Image(IMG img, VOID *v)
{
    for( SEC sec=IMG_SecHead(img); SEC_Valid(sec) ; sec=SEC_Next(sec) )
    {
        if ( SEC_IsExecutable(sec) )
        {
            for( RTN rtn=SEC_RtnHead(sec); RTN_Valid(rtn) ; rtn=RTN_Next(rtn) )
                 Routine( img, rtn,v);
        }
    }
}

VOID Instruction(INS ins, VOID *v)
{
	// Instruments memory accesses using a predicated call, i.e.
	// the instrumentation is called iff the instruction will actually be executed.
	//
	// On the IA-32 and Intel(R) 64 architectures conditional moves and REP 
	// prefixed instructions appear as predicated instructions in Pin.
	UINT32 memOperands = INS_MemoryOperandCount(ins);

	// Iterate over each memory operand of the instruction.
	for (UINT32 memOp = 0; memOp < memOperands; memOp++)
	{
		if (INS_MemoryOperandIsRead(ins, memOp))
		{
			INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
					IARG_INST_PTR,
					IARG_MEMORYOP_EA, memOp,
					IARG_THREAD_ID,
					IARG_END);
		}
		// Note that in some architectures a single memory operand can be 
		// both read and written (for instance incl (%eax) on IA-32)
		// In that case we instrument it once for read and once for write.
		if (INS_MemoryOperandIsWritten(ins, memOp))
		{
			INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
					IARG_INST_PTR,
					IARG_MEMORYOP_EA, memOp,
					IARG_THREAD_ID,
					IARG_END);
		}
	}
}

// This routine is executed once at the end.
VOID Fini(INT32 code, VOID *v) {
	fclose(out);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage() {
	PIN_ERROR("This Pintool prints a trace of malloc calls in the guest application\n"
			+ KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(INT32 argc, CHAR **argv) {
	// Initialize the pin lock
	PIN_InitLock(&pinLock);

	// Initialize pin
	if (PIN_Init(argc, argv))
		return Usage();

	// Initialize pin & symbol manager
	PIN_InitSymbolsAlt(SYMBOL_INFO_MODE(UINT32(IFUNC_SYMBOLS)));

	out = fopen(KnobOutputFile.Value().c_str(), "w");

	// Register Analysis routines to be called when a thread begins/ends
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddSyscallExitFunction(SyscallExit, 0);

	// Register Image to be called to instrument functions.
	IMG_AddInstrumentFunction(Image, 0);
	
	INS_AddInstrumentFunction(Instruction, 0);

	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Never returns
	PIN_StartProgram();

	return 0;
}
