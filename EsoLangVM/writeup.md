4d5a9000's EsoLangVM Test
https://crackmes.one/crackme/644d347733c5d43938912cd7

# Challenge

x86 elf executable
Atypical control flow due to unconventional compilation,
though not intentionally obfuscated (per author's notes.)

Prompt:

```
KeyGenMe V1.0
Name: [waits for input]
Key:
```

A valid Name/Key pair was provided by the author:

```
KeyGenMe V1.0
Name: Alice
Key: 496c63-4a69-644f-6a79-50777a55707f56
You did it, Alice! Congratulations!
Registration Succeeded
```

Failure response:
```
Name: Alice
Key: 496c63-4a69-644f-6a79-50777a55707f57
Sorry, but your key is invalid.
Registration Failed
```

Entering a key with arbitrary format elicits:
```
Key format is incorrect. Please check again.
Registration Failed
```

# First glance

Exploring in IDA immediately lets us in on the strange world we have chosen to enter.
Initially something is dynamically built up via large swaths of mov instructions,
reminiscent of the mov-only compiler (https://github.com/xoreaxeaxeax/movfuscator)

Thankfully the whole thing isn't written this way.

Console reads and writes, and memory allocation are performed directly with int 0x80 syscalls.
If we search the code base for syscalls, we find wrapper function stubs for different types of read and write operations.

The entry points and exit destinations for these can be reached from any of a number of jumptable entries in different locations,
which strongly suggests we're dealing with some sort of virtualization, which can often be quite difficult to make sense out of.

There has been a lot of work put into automated methods for de-virtualizing programs.
(Eg. "Automatic Reverse Engineering of Malware Emulators" https://sci-hub.live/10.1109/SP.2009.27)

If we pay close attention, though, we'll notice that we actually may have caught a lucky break this time.

Here is the entry point to one of the read stubs:

```
LOAD:0010D1B1 loc_10D1B1:                             ; CODE XREF: LOAD:00101DFB↑j
LOAD:0010D1B1                                         ; LOAD:00101F6C↑j ...
LOAD:0010D1B1                 push    edi             ; jumptable 00101DFB case 577
LOAD:0010D1B1                                         ; jumptable 00101F6C case 577
LOAD:0010D1B1                                         ; jumptable 00101FED case 577
LOAD:0010D1B1                                         ; jumptable 00102705 case 577
```

And to one of the write stubs:

```
LOAD:001042F0 loc_1042F0:                             ; CODE XREF: LOAD:00101DFB↑j
LOAD:001042F0                                         ; LOAD:00101F6C↑j ...
LOAD:001042F0                 mov     ebx, ebp        ; jumptable 00101DFB case 133
LOAD:001042F0                                         ; jumptable 00101F6C case 133
LOAD:001042F0                                         ; jumptable 00101FED case 133
LOAD:001042F0                                         ; jumptable 00102705 case 133
```

Notice anything?
Even though they can be reached from multiple different jumptables, each stub appears to be the same entry in every one of them.

The stubs are actually all stored in the code base in numerical order, and execution flows from one stub to another based mostly on simple decisions made by each one.
We'd really prefer not to have to characterize all of these, only the ones relevant to our goal of understanding the key validation.

The plan is to generate a list of stub addresses by case number, and then to trace execution through parts of the program we care about
to see how the relevant ones get strung together.

Then we can look at what each of those actually does, so we can "disassemble" the chain of stubs executed into something followable.

If we skim through the docs for ELVM (https://github.com/shinh/elvm),
our suspicions of virtualization seem to be confirmed:

```
6 registers: A, B, C, D, SP, and BP
Ops: mov, add, sub, load, store, setcc, jcc, putc, getc, and exit
Psuedo ops: .text, .data, .long, and .string
```

We have hundreds of stub functions, though, and it would likely take a thorough understanding of how ELVM builds its intermediate representation,
then how 8cc compiles that to bytecode to understand what's mapped to what from that side.

We'll stick to understanding how the bytecode works and not worry about what any of it translates to in ELVM's language description.
As a side note for now, skimming through the code a bit, we can see the output strings getting loaded a char at a time starting at 00100BCF.

# Building the macro list

The "proper" way to go about doing this would probably be through a Python script loaded into IDA,
but the subsystem for interacting with the debugger varies between IDA versions and it's all kind of finicky.

I just saved a copy of the full disassembly listing (listing.txt).
We can open it in Notepad++ and search for all instances of "jumptable 00101DFB case",
since that table seems to be the first xref to each stub and appears in its comments:

```
	Line   606: LOAD:0010152A                 jmp     loc_111224      ; jumptable 00101DFB case 0
	Line   650: LOAD:0010152F                 mov     edx, edi        ; jumptable 00101DFB case 1
	Line   745: LOAD:00101600                 mov     ebx, ebp        ; jumptable 00101DFB case 2
	Line   877: LOAD:00101773                 jz      short loc_10177A ; jumptable 00101DFB case 3
	Line   917: LOAD:00101775                 jmp     loc_1017DA      ; jumptable 00101DFB case 4
	Line   961: LOAD:0010177A                 mov     ebx, ebp        ; jumptable 00101DFB case 3
	Line  1027: LOAD:001017DA                 mov     eax, ebx        ; jumptable 00101DFB case 4
	...
```

You can see that many of the case numbers show up twice.
This is because one of them comes from the cross reference list at the actual destination stub,
and the other comes from comments beside of jumps to this destination
(Ie. "Hey, the address you're jumping to has these other xrefs also.")

We just need to ditch the lines with branch instructions (jmp, jz, jnz, etc.)
Go back to the listing and do a regex search for "^(?!.*j.{2,3} ).*jumptable 00101DFB case" (search.txt):

```
	Line   650: LOAD:0010152F                 mov     edx, edi        ; jumptable 00101DFB case 1
	Line   745: LOAD:00101600                 mov     ebx, ebp        ; jumptable 00101DFB case 2
	Line   961: LOAD:0010177A                 mov     ebx, ebp        ; jumptable 00101DFB case 3
	Line  1027: LOAD:001017DA                 mov     eax, ebx        ; jumptable 00101DFB case 4
	...
```

We're missing a few of them (eg. case 5), but these just seem to be jumps to other numbered macros (case 5 just jumps to case 8.)
We can go back and fill them in if they appear to become a problem.

Now we just need to trace through execution and log when we're hitting each of these addresses during validation,
work out what each one that gets used does, and then we can effectively decompile it into a sequence of actions.

# Macro sequence tracing: Name

Let's see what happens after the Name gets read.

The general plan here is to launch the program, which will display the banner and Name request then hang on the read syscall waiting for out input.
Then we can attach with gdb, run a script to set silent breakpoints on all of our stubs that just log when they are hit, tell gdb to catch the write syscall,
so we can focus just on what happens up until it asks for the Key, then we can see the chain of stubs used and work out what they do.

There are several ways to approach this.

## Basic gdb scripting

We could just build up a command script using python to log all of the macro entrypoints we hit:

(gdbcmd.py)
```
#!/usr/bin/python3
import re

break_cmd = '''break *0x{0}
commands
silent
print "{0} {1}"
cont
end'''

def add_break(addr, case):
    print(break_cmd.format(addr, case))

with open("search.txt") as file:
    for line in file:
        args = re.search("LOAD:([0-9A-F]{8}).* case ([0-9]*)$", line)
        if args:
            add_break(args[1], args[2])
```

We can pipe the output to a file like (gdb.cmd)
We start up keygenme.elf, then switch to another shell and attach gdb.

If you're on Ubuntu, you're going to have to edit /proc/sys/kernel/yama/ptrace_scope to contain 0 in order for attachment to work,
or you'll have to debug as root. The scope will only remain changed until reboot unless you edit /etc/sysctl.d/10-ptrace.conf as well.
https://unix.stackexchange.com/questions/329504/proc-sys-kernel-yama-ptrace-scope-keeps-resetting-to-1

```
$ sudo sh -c "echo 0 > /proc/sys/kernel/yama/ptrace_scope"
$ ps -a | grep "keygen"
  47295 pts/0    00:00:00 keygenme.elf
$ gdb -p 47295
(gdb) x/3i $pc
=> 0x10fae5:	pop    %edi
   0x10fae6:	mov    $0x0,%ebx
   0x10faeb:	cmp    $0x1,%eax
```
We can see we are in the middle of macro 686, which reads a single char from stdin,
and we are currently waiting on the syscall to return.

```
(gdb) catch syscall write
Catchpoint 1 (syscall 'write' [4])
(gdb) source gdb.cmd
Breakpoint 2 at 0x10152f
Breakpoint 3 at 0x101600
Breakpoint 4 at 0x10177a
...
```

Make sure you don't use 'q' to quit out of the listing or you'll stop the script from setting all of the breakpoints.  Use 'c' or just hit return to step through it.
You can use "set pagination off" at the beginning of your script if you want to auto-skip through this (just remember to turn it back on at the end if you like using it.)

```
(gdb) set logging file name.txt
(gdb) set logging enabled on

Copying output to name.txt.
Copying debug output to name.txt.
```

Go over to the shell that keygenme.elf is open in, type in "Alice" for the name,  and hit enter, then come back over to gdb and type 'c' to continue:

```
(gdb) c
Continuing.
$1 = "0010FB0A 688"
$2 = "0010FC30 689"
$3 = "0010FA69 685"
$4 = "0010FACB 686"
$5 = "0010FB0A 688"
$6 = "0010FC30 689"
$7 = "0010FA69 685"
$8 = "0010FACB 686"
...
$303 = "001042C3 130"
$304 = "001042F0 133"

Catchpoint 1 (call to syscall write), 0x00104334 in ?? ()
```

Cool! We can already see a read loop cycling around, so we've probably set things up correctly.
(We broke in at 686, which does the read syscall, and we can see it cycling around to it repeatedly.)

This way is going to get really clumsy really quickly when it comes to some things we want to do with gdb later.
Thankfully gdb actually has its own python integration, but only for python scripts run within gdb.

## Using the gdb python api

The following python script does the same thing as our command script above,
but gives us a much cleaner way to set breakpoints and more control over what happens when they are reached:

(gdbpy.py)
```
import gdb
import re

# Breakpoint handler
class macro_bp(gdb.Breakpoint):
    def __init__(self, address, name):
        self.address = address
        self.name = name
        gdb.Breakpoint.__init__(self, f"*0x{address}")
        self.silent = True  # Don't announce when the breakpoint is hit
        
    def stop(self):
        print(name)
        return False        # Continue execution

macros = []

# Get initial pagination state and turn off pagination
page_state = gdb.execute("show pagination", False, True).strip()[-4:-1].strip()
gdb.execute("set pagination off", False)

with open("search.txt") as file:
    for line in file:
        args = re.search("LOAD:([0-9A-F]{8}).* case ([0-9]*)$", line)
        if args:
            macros.append(macro_bp(args[1], args[2]))

# Reset pagination to original state
gdb.execute(f"set pagination {page_state}", False)
```

We run it using the source command just like with the command script:
```
(gdb) source gdbpy.py
Breakpoint 2 at 0x10152f
Breakpoint 3 at 0x101600
Breakpoint 4 at 0x10177a
```

We get the same output in this particular use case, but you can see how it's a lot more flexible and offers more control.
I planned to script gdb to get extract all of the information we need during execution tracing later,
but it quickly became unwieldy and I had to go with a different solution.

This seemed like good information worth leaving in, though.

# Characterizing macros: Name

If we find/replace the double quotes in (name.txt), and copy the whole thing into a spreadsheet to filter by unique macro numbers,
we can see that there are 49 macros that get used to read and process the Name input (nameunique.txt)

There are analysis tools available to help lift assembly to intermediate representations and try to simplify them,
such as Triton (https://triton-library.github.io/) and angr (https://angr.io/).
The learning curve is a bit steep, and you still need an idea of what you're dealing with to get useful results with them.

If we were trying to simplify complex stretches of code with lots of instructions that have side effects,
then we would absolutely need to employ one of these frameworks to try to reduce it, but that doesn't appear to be what we're facing.

We can start working through some of the macros manually to look for any patterns we might be able to use to automate simplifying them.

We can see that 686 is effectively getchar(), just a simple syscall wrapper.
Macro 688 is more representative of the type of code stubs we need to understand, and we do see a pattern that repeatedly reappears elsewhere.
See my manual breakdown in (688_manual.txt).  You'll notice I have split it into two sections, the data/math section and the conditional section.

The tedious data/math section follows a similar pattern in every macro.
It's made up of very simple reads and writes from a table pointed to by esi and some basic math,
and it only uses a handful of instructions with no side effects.

Can we write our own junky lifting engine that will simplify these limited cases?
This is explorered in the accompanying (lifting.md) and (lifting.py)

Using (lifting.py) on macro 688, we can successfully print the same annotations we came up with manually,
as well as produce a simplified version of the code along with all the relevant inputs and outputs (registers left tainted.)

esi() in the reduced format refers to indexing a uint32_t from an array of them that starts at esi.
Parentheses were chosen over brackets [] to avoid confusing the indexes with memory addresses.
Ie. 'esi(index)' is equivalent to '[esi+index*4]'

```
$ python3 lifting.py macros/688.txt

Inputs:
in(edi): edi
in(eax): eax
in(ebp): ebp
...
Reduced:
esi(in(edi) - 1) = in(eax)
esi(in(edi) - 2) = in(ebp) + 2
esi(in(edi) - 3) = esi(in(ebp) + 2)
esi(in(edi) - 4) = esi(in(ebp) - 1)
esi(in(ebp) - 1) = esi(in(ebp) - 1) + 1
esi(esi(in(ebp) + 2) + esi(in(ebp) - 1)) = in(eax)
esi(in(edi) - 1) = in(eax)

Outputs:
out(edx): in(edi) - 1
out(edi): in(edi)
out(ebx): 10
out(eax): in(eax)
out(ecx): esi(in(ebp) + 2) + esi(in(ebp) - 1)

Unprocessed:
LOAD:0010FC16                 cmp     eax, ebx
LOAD:0010FC18                 mov     eax, 0
LOAD:0010FC1D                 setnz   al
LOAD:0010FC20                 mov     ebx, eax
LOAD:0010FC22                 cmp     ebx, 0
LOAD:0010FC28                 mov     ebx, 0
LOAD:0010FC2D                 setnz   bl
```

All of the math and memory operations are worked out for us, and we can just focus on the conditional at the end.
Here the conditional just checks for a newline character.

We can already start to string together macros and get some idea of what's going on through static analysis.
That doesn't give us a very complete picture though, since many pre-existing important values are read from the table.

It would be nice to have an execution trace that gives us the macros in their reduced forms,
along with the relevant variable values at each step.

# Simplified execution tracing: Name

I originally tried to use a python script to setup tons of breakpoints that could print the information we need as they are reached,
but it was a messy solution and would require re-tracing the program anytime we need to adjust the outputs.

The most sensible solution (given my experience, at least) was to just write a Pin tool to trace through and extract everything we care about.

