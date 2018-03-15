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
#include "pin.H"

#define TRUE		1
#define FALSE		0
#define PAGE_SHIFT	12
#define PAGE_MASK	(~(PAGE_SIZE - 1))

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

typedef struct threadNode {
	THREADID tid;
	void *args;
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
	char name[20];
	char filename[128];
	unsigned long reqAddr;
	size_t length;
	int prot;
	int flags;
	int fd;
	off_t offset;
} MmapArgs;

typedef struct munmapArgs {
	char name[20];
	unsigned long start;
	size_t length;
} MunmapArgs;

int findMemNode(unsigned long addr, unsigned long *pgoff, THREADID tid) {
	MemNode *curr = memNodeHead;

	while (curr) {
		if ((curr->start <= addr) && (addr < curr->end)) {
			*pgoff = ((addr & PAGE_MASK) - curr->start) >> PAGE_SHIFT;
			return TRUE;
		}
		curr = curr->next;
	}
	return FALSE;
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
	newNode->args = NULL;
	newNode->next = NULL;

	if (threadNodeHead == NULL)
		threadNodeHead = newNode;
	if (threadNodeTail != NULL)
		threadNodeTail->next = newNode;
	threadNodeTail = newNode;
	//fprintf(out, "[%d] %s: A threadNode was inserted into the threadNode list.\n", tid, __func__);
	return TRUE;
}

int deleteMemNode(unsigned long start, unsigned long length, THREADID tid) {
	MemNode *prev = NULL;
	MemNode *curr = memNodeHead;

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
			return TRUE;
		}
		prev = curr;
		curr = curr->next;
	}
	fprintf(out, "[%d] %s: This memNode can not be deleted. (ERROR)\n", tid, __func__);
	return FALSE;
}

int deleteThreadNode(THREADID tid) {
	ThreadNode *prev = NULL;
	ThreadNode *curr = threadNodeHead;

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
			return TRUE;
		}
		prev = curr;
		curr = curr->next;
	}
	fprintf(out, "[%d] %s: This threadNode can not be deleted. (ERROR)\n", tid, __func__);
	return FALSE;
}

int putArgs(THREADID tid, void *args) {
	ThreadNode *curr = threadNodeHead;

	while (curr) {
		if (curr->tid == tid) {
			curr->args = args;
			//fprintf(out, "[%d] %s: Args were saved in the threadNode.\n", tid, __func__);
			return TRUE;
		}
	}
	fprintf(out, "[%d] %s: This args can not be saved. (ERROR)\n", tid, __func__);
	return FALSE;
}

void *getArgs(THREADID tid) {
	ThreadNode *curr = threadNodeHead;

	while (curr) {
		if (curr->tid == tid) {
			return curr->args;
		}
	}
	fprintf(out, "[%d] %s: This node has no args. (ERROR)\n", tid, __func__);
	return FALSE;
}

// Note that opening a file in a callback is only supported on Linux systems.
// See buffer-win.cpp for how to work around this issue on Windows.
//
// This routine is executed every time a thread is created.
VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
	PIN_GetLock(&pinLock, tid+1);
	fprintf(out, "[%d] thread begin\n",tid);
	fflush(out);
	insertThreadNode(tid);
	PIN_ReleaseLock(&pinLock);
}

// This routine is executed every time a thread is destroyed.
VOID ThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 code, VOID *v) {
	PIN_GetLock(&pinLock, tid+1);
	fprintf(out, "[%d] thread end\n",tid);
	fflush(out);
	deleteThreadNode(tid);
	PIN_ReleaseLock(&pinLock);
}

// This routine is executed each time memcpy() is called.
VOID BeforeMemcpy(char *name, unsigned long dst, unsigned long src, unsigned long size, THREADID tid) {
	PIN_GetLock(&pinLock, tid+1);
	fprintf(out, "[%d] %s-call (0x%lx, 0x%lx, %lu)\n", tid, name, dst, src, size);
	fflush(out);
	PIN_ReleaseLock(&pinLock);
}

VOID AfterMemcpy(char *name, unsigned long ret, THREADID tid) {
	PIN_GetLock(&pinLock, tid+1);
	fprintf(out, "[%d] %s-return (0x%lx)\n", tid, name, ret);
	fflush(out);
	PIN_ReleaseLock(&pinLock);
}

// This routine is executed each time mmap() is called.
VOID BeforeMmap(char *name, unsigned long reqAddr, size_t length, int prot, int flags, 
		int fd, off_t offset, THREADID tid) {
	MmapArgs *args;
	int pid;
	char *path, *filename;
	ssize_t result;

	/* get filename */
	pid = PIN_GetPid();
	path = (char *)malloc(128);
	filename = (char *)malloc(128);
	strcpy(path, "/proc/");
	sprintf(&path[strlen(path)], "%d", pid);
	strcat(path, "/fd/");
	sprintf(&path[strlen(path)], "%d", fd);

	PIN_GetLock(&pinLock, tid+1);
	if (offset != 0) {
		fprintf(out, "[%d] %s: offset is not 0. (ERROR)\n", tid, __func__);
		fflush(out);
		exit(-1);
	}

	result = readlink(path, filename, 128);
	if (result < 0) {
		fprintf(out, "[%d] %s: readlink() failed (ERROR)\n", tid, __func__);
		fflush(out);
		exit(-1);
	}

	args = (MmapArgs *)malloc(sizeof(MmapArgs));
	if (args == NULL) {
		fprintf(out, "[%d] %s: malloc() failed (ERROR)\n", tid, __func__);
		fflush(out);
		exit(-1);
	}

	fprintf(out, "[%d] %s-call (0x%lx, %lu, 0x%x, 0x%x, %s, %ld)\n",
			tid, name, reqAddr, length, prot, flags, filename, offset);
	fflush(out);

	strcpy(args->name, name);
	strcpy(args->filename, filename);
	args->reqAddr = reqAddr;
	args->length = length;
	args->prot = prot;
	args->flags = flags;
	args->fd = fd;
	args->offset = offset;
	putArgs(tid, (void *)args);
	PIN_ReleaseLock(&pinLock);
}

VOID AfterMmap(char *name, unsigned long ret, THREADID tid) {
	MmapArgs *args;
	unsigned long start, end, nrpages;
	int result;
	PIN_GetLock(&pinLock, tid+1);
	args = (MmapArgs *)getArgs(tid);

	if (strcmp(args->name, name) == 0) {
		start = ret;
		end = start + args->length;
		nrpages = args->length >> PAGE_SHIFT;

		result = insertMemNode(args->filename, start, end, args->length, nrpages, tid);

		if (result) {
			fprintf(out, "[%d] %s-return (0x%lx, %lu, 0x%x, 0x%x, %s, %ld)=0x%lx\n",
					tid, args->name, args->reqAddr, args->length, args->prot,
					args->flags, args->filename, args->offset, ret);
		}
		else {
			fprintf(out, "[%d] %s: insertMemNode failed. (ERROR)\n", tid, __func__);
			fflush(out);
			exit(-1);
		}

	} else {
		fprintf(out, "[%d] %s: FuncName and args do not match. (ERROR)\n", tid, __func__);
		fflush(out);
		exit(-1);
	}
	fflush(out);
	PIN_ReleaseLock(&pinLock);
}

// This routine is executed each time munmap() is called.
VOID BeforeMunmap(char *name, unsigned long reqAddr, size_t length, THREADID tid) {
	MunmapArgs *args;

	PIN_GetLock(&pinLock, tid+1);

	args = (MunmapArgs *)malloc(sizeof(MunmapArgs));
	if (args == NULL) {
		fprintf(out, "[%d] %s: malloc() failed (ERROR)\n", tid, __func__);
		fflush(out);
		exit(-1);
	}

	fprintf(out, "[%d] %s-call (0x%lx, %lu)\n", tid, name, reqAddr, length);
	fflush(out);

	strcpy(args->name, name);
	args->start = reqAddr;
	args->length = length;
	putArgs(tid, (void *)args);
	PIN_ReleaseLock(&pinLock);
}

VOID AfterMunmap(char *name, unsigned long ret, THREADID tid) {
	MunmapArgs *args;
	int result;

	PIN_GetLock(&pinLock, tid+1);
	args = (MunmapArgs *)getArgs(tid);

	if (strcmp(args->name, name) == 0) {
		result = deleteMemNode(args->start, args->length, tid);

		if (result) {
			fprintf(out, "[%d] %s-return (0x%lx, %lu)=0x%lx\n",
					tid, args->name, args->start, args->length, ret);
		}
		else {
			fprintf(out, "[%d] %s: deleteMemNode failed. (ERROR)\n", tid, __func__);
			fflush(out);
			exit(-1);
		}

	} else {
		fprintf(out, "[%d] %s: FuncName and args do not match. (ERROR)\n", tid, __func__);
		fflush(out);
		exit(-1);
	}
	fflush(out);
	PIN_ReleaseLock(&pinLock);
}


//====================================================================
// Instrumentation Routines
//====================================================================

VOID Routine(IMG img, RTN rtn, void *v) {
	bool isMemmove = strcmp(RTN_Name(rtn).c_str(),"memmove")==0;
	bool isMemcpy = strcmp(RTN_Name(rtn).c_str(),"memcpy")==0;
	bool isMmap = strcmp(RTN_Name(rtn).c_str(),"mmap")==0;
	bool isMunmap = strcmp(RTN_Name(rtn).c_str(),"munmap")==0;

	if (SYM_IFuncResolver(RTN_Sym(rtn))) {
		printf("IFUNC resolver symbol.\n");
	}
	else {
		if (isMemmove || isMemcpy) {
			RTN_Open(rtn);

			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)BeforeMemcpy,
					IARG_ADDRINT, RTN_Name(rtn).c_str(),
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
					IARG_THREAD_ID,
					IARG_END);

			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AfterMemcpy,
					IARG_ADDRINT, RTN_Name(rtn).c_str(),
					IARG_FUNCRET_EXITPOINT_VALUE,
					IARG_THREAD_ID,
					IARG_END);

			RTN_Close(rtn);
		}

		if (isMmap) {
			RTN_Open(rtn);

			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)BeforeMmap,
					IARG_ADDRINT, RTN_Name(rtn).c_str(),
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
					IARG_THREAD_ID,
					IARG_END);

			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AfterMmap,
					IARG_ADDRINT, RTN_Name(rtn).c_str(),
					IARG_FUNCRET_EXITPOINT_VALUE,
					IARG_THREAD_ID,
					IARG_END);

			RTN_Close(rtn);
		}

		if (isMunmap) {
			RTN_Open(rtn);

			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)BeforeMunmap,
					IARG_ADDRINT, RTN_Name(rtn).c_str(),
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					IARG_THREAD_ID,
					IARG_END);

			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AfterMunmap,
					IARG_ADDRINT, RTN_Name(rtn).c_str(),
					IARG_FUNCRET_EXITPOINT_VALUE,
					IARG_THREAD_ID,
					IARG_END);

			RTN_Close(rtn);
		}
	}
}

// This routine is executed for each image.
VOID ImageLoad(IMG img, VOID *v) {
	for (SEC sec=IMG_SecHead(img); SEC_Valid(sec); sec=SEC_Next(sec)) {
		if (SEC_IsExecutable(sec)) {
			for(RTN rtn=SEC_RtnHead(sec); RTN_Valid(rtn); rtn=RTN_Next(rtn))
				Routine(img, rtn, v);
		}
	}
}

// Print a memory read record
VOID RecordMemRead(VOID * ip, VOID * addr, THREADID tid) {
	unsigned long pgoff;
	unsigned long address = (unsigned long)addr;

	PIN_GetLock(&pinLock, tid+1);
	if (findMemNode(address, &pgoff, tid)) {
		fprintf(out,"[%d] %p: R 0x%lx (%lu)\n", tid, ip, address, pgoff);
		fflush(out);
	}
	PIN_ReleaseLock(&pinLock);
}

// Print a memory write record
VOID RecordMemWrite(VOID * ip, VOID * addr, THREADID tid) {
	unsigned long pgoff;
	unsigned long address = (unsigned long)addr;

	PIN_GetLock(&pinLock, tid+1);
	if (findMemNode(address, &pgoff, tid)) {
		fprintf(out,"[%d] %p: W 0x%lx (%lu)\n", tid, ip, address, pgoff);
		fflush(out);
	}
	PIN_ReleaseLock(&pinLock);
}

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v) {
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
	if (PIN_Init(argc, argv)) return Usage();
	PIN_InitSymbolsAlt(SYMBOL_INFO_MODE(UINT32(IFUNC_SYMBOLS)));

	out = fopen(KnobOutputFile.Value().c_str(), "w");

	// Register ImageLoad to be called when each image is loaded.
	IMG_AddInstrumentFunction(ImageLoad, 0);

	// Register Analysis routines to be called when a thread begins/ends
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	INS_AddInstrumentFunction(Instruction, 0);

	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Never returns
	PIN_StartProgram();

	return 0;
}
