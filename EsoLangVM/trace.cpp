#include <iostream>
#include <fstream>
#include "pin.H"

// Command line arguments
KNOB<std::string> out_filename(KNOB_MODE_WRITEONCE, "pintool", "o", "trace.out", "specify trace file name");

// Globals
std::ofstream logfile;
char *sysread_buf = 0;

class save_inputs
{
	bool saving, saving_name;

public:
	std::string name;
	std::string key;

	save_inputs() : saving(true), saving_name(true) {}
	void push_back(char c);
};

void save_inputs::push_back(char c)
{
	if (saving)
		if (saving_name)
		{
			if (c != '\n')
				name.push_back(c);
			else
				saving_name = false;
		}
		else
		{
			if (c != '\n')
				key.push_back(c);
			else
				saving = false;
		}
}

save_inputs inputs;

// Save input buffer for getchar() equivalent syscall
VOID SyscallEntry(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
	if ((PIN_GetSyscallNumber(ctxt, std) == 0x03) &&	// read
		(PIN_GetSyscallArgument(ctxt, std, 0) == 0) &&	// stdin
		(PIN_GetSyscallArgument(ctxt, std, 2) == 1))	// size = 1
	{
		sysread_buf = (char *) PIN_GetSyscallArgument(ctxt, std, 1);	// read buffer
	}
}

// Save characters on return from getchar() equivalent syscall-+
-
VOID SyscallExit(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
	if (sysread_buf)
	{
		inputs.push_back(*sysread_buf);
		sysread_buf = 0;
	}
}

VOID Fini(INT32 code, VOID* v)
{
	logfile << "Name:\t" << inputs.name << std::endl;
	logfile << "Key:\t" << inputs.key << std::endl;
	logfile.close();
}

int main(int argc, char* argv[])
{
	PIN_Init(argc, argv);

	logfile.open(out_filename.Value().c_str());
	
	if (!logfile)
	{
		std::cout << "Could not open log file " << out_filename.Value().c_str() << std::endl;
		exit(1);
	}

	// Add instrumentation functions
	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddSyscallExitFunction(SyscallExit, 0);

	PIN_AddFiniFunction(Fini, 0);

	// Never returns
	PIN_StartProgram();

	return 0;
}
