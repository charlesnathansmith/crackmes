# Overview

**sporta778's Bobby**  
<https://crackmes.one/crackme/65e84aed199e6a5d372a4135>

```
Bobby is ill! Can you help to Bobby?
```

# Challenge

```
$ file random.exe
random.exe: PE32+ executable (console) x86-64, for MS Windows
```

Prompt:
```
Hello! I am Bobby ! Can you heal me? Please!
 00000
0     0
0 0 0 0
0  0  0
0     0
0 000 0
0     0
 00000


 Ç0☻►@☻
0♦►☻0
  @ 0 0
☻☻Ç☻0
0  Ç  Ç
0☻0☻☻♦
0Ç Ç  ♦
 0Ç000Ç


Enter name of medicine for Bobby!!password

This is bad medicine for Bobby.
```

Dang it, Bobby...
```
⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠈⢷⡀⠀⠀⠀
⢸⣿⣿⣿⣿⣿⣿⣿⠟⠉⠀⠀⠀⠀⠀⠀⠀⣀⠤⠤⠀⠀⠀⠀⠀⠀⢻⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠉⣀⠤⠤⢄⡀⠀⠀⠀⠀⢾⠀⠀⠀
⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣸⣦⣀⠀
⣿⣿⣿⣿⣿⣿⠇⠀⠀⢀⣀⣠⣤⣤⣤⣴⣶⣶⣦⣤⣤⣾⡟⠋⢉⡉⠁⡟⢿⡄
⣿⣿⣿⣿⣿⣿⢂⣠⡾⣿⠋⠉⠁⢠⣦⢄⠀⠈⣿⠀⠀⣿⡇⢴⡻⣷⡢⣧⢸⣷
⢻⣿⣿⣿⣿⣿⠟⠉⠀⣿⡀⠀⢞⣁⣛⠤⠃⠀⣿⠀⠀⢸⣷⣀⣸⣖⣀⣸⣿⡿
⢠⡟⠋⠻⠿⠟⠀⠀⠀⢿⣧⣤⣤⣴⣾⣿⡤⠶⠟⠀⠀⠀⠻⡉⠉⠉⠁⠀⠈⣷
⢸⣄⠈⢹⠂⠀⠀⠀⠀⠀⠉⠉⠉⠁⠀⠀⠀⠀⢀⡄⠀⠀⠀⠙⠢⢄⠀⠀⠀⣿
⠀⠹⣦⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⢏⡤⢤⣀⣀⡠⠏⠀⠀⠐⢲⡇
⠀⠀⠘⣷⠂⠀⠀⠀⠀⠀⠀⣀⠀⠀⠤⠂⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⢸⡇
⠀⠀⠀⢹⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣊⣯⣽⣵⣷⡇⠀⠀⠀⡇
⠀⠀⠀⠈⣧⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⡿⠿⠛⠃⠀⠀⠀⣇
⠀⠀⠀⠀⢹⡀⠀⠹⡄⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠋⠉⠠⠒⠂⠀⠀⠀⠀⠀⢸
⠀⠀⠀⠀⠘⡇⠀⠀⠱⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠏
⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⠴⠀⡏
```

# Diving in

We can open the target in IDA and look around to find where the input is received:
```
.text:000000014000138F lea     rcx, aEnterNameOfMed ; "Enter name of medicine for Bobby!!"
.text:0000000140001396 call    sub_140001020
.text:000000014000139B mov     r8d, 39h ; '9'
.text:00000001400013A1 lea     rdx, [rbp+password]
.text:00000001400013A5 lea     rcx, aS         ; "%s"
.text:00000001400013AC call    sub_140001080   ; vfscanf
```

A lot of mathy things happen to it, and then we get our result:
```
.text:0000000140001AA2 cmp     al, cs:byte_14000505A
.text:0000000140001AA8 lea     rax, aThisIsBadMedic ; "This is bad medicine for Bobby."
.text:0000000140001AAF lea     rcx, aThanksBobbyNow ; "Thanks! Bobby now is cured!"
.text:0000000140001AB6 lea     edx, [r8+1]
.text:0000000140001ABA cmovnz  edx, r8d
.text:0000000140001ABE cmp     edx, 38h ; '8'
.text:0000000140001AC1 cmovnz  rcx, rax        ; Format
.text:0000000140001AC5 call    sub_140001020   ; puts
```

There aren't any critical library calls in between, so this may be something we can get [angr](https://angr.io/) to deal with if we're careful about it.

# Massaging the binary

angr can load PE files, but it doesn't have copies of all the libraries most Windows executables rely on, and it can't process Windows syscalls at all.  If we have a very self-contained piece of code that dodges all of these landmines, then angr can make sense of it.

We'll start by removing the decorative output after entering the password, so that this:
```
.text:000000014000161E lea     rcx, asc_140003300 ; "\n\n"
.text:0000000140001625 call    sub_140001020
.text:000000014000162A lea     rcx, byte_140005094
.text:0000000140001631 call    sub_1400010E0
.text:0000000140001636 lea     rcx, byte_1400050AC
.text:000000014000163D call    sub_1400010E0
.text:0000000140001642 lea     rcx, byte_14000506C
.text:0000000140001649 call    sub_1400010E0
.text:000000014000164E lea     rcx, byte_14000503C
.text:0000000140001655 call    sub_1400010E0
.text:000000014000165A lea     rcx, byte_140005044
.text:0000000140001661 call    sub_1400010E0
.text:0000000140001666 lea     rcx, byte_1400050A4
.text:000000014000166D call    sub_1400010E0
.text:0000000140001672 lea     rcx, byte_140005034
.text:0000000140001679 call    sub_1400010E0
.text:000000014000167E lea     rcx, byte_14000508C
.text:0000000140001685 call    sub_1400010E0
.text:000000014000168A movzx   eax, cs:byte_14000504C
```

Becomes this:
```
.text:000000014000161E EB 6A                   jmp     short loc_14000168A
...
.text:000000014000168A movzx   eax, cs:byte_14000504C
```

We don't need to patch anything up through the input prompt because we can just tell angr to start after it, and will mark the password buffer as symbolic there.

The original result decision looks like this:
```
.text:0000000140001AA2 cmp     al, cs:byte_14000505A
.text:0000000140001AA8 lea     rax, aThisIsBadMedic ; "This is bad medicine for Bobby."
.text:0000000140001AAF lea     rcx, aThanksBobbyNow ; "Thanks! Bobby now is cured!"
.text:0000000140001AB6 lea     edx, [r8+1]
.text:0000000140001ABA cmovnz  edx, r8d
.text:0000000140001ABE cmp     edx, 38h ; '8'
.text:0000000140001AC1 cmovnz  rcx, rax        ; replaces success msg ptr with failure msg ptr
.text:0000000140001AC5 call    sub_140001020
```

The simplest way to find paths in angr is to provide it 'find' and 'avoid' addresses, which we can have it do:
```
.text:0000000140001ABE 83 FA 38                                cmp     edx, 38h ; '8'
.text:0000000140001AC1 75 01                                   jnz     short locret_140001AC4
.text:0000000140001AC3 C3                                      retn        ; find
.text:0000000140001AC4 C3                                      retn        ; avoid
```

We don't need to worry about what it tries to return to since we'll be telling angr to always stop at one of these.

From the size reserved for the password buffer and some sections like this:
```
.text:00000001400013E0 loc_1400013E0:
.text:00000001400013E0 add     byte ptr [rbp+rax+var_50], 0D0h
.text:00000001400013E5 inc     rax
.text:00000001400013E8 cmp     rax, 38h ; '8'
.text:00000001400013EC jl      short loc_1400013E0
```

It seems reasonable to assume that the password is probably 38h (dec 56) characters long, which we'll need to know.

# Unleashing our angr

```
# solver.py
import angr, claripy

BINARY_PATH = './patched.exe'

# Create the project
p = angr.Project(BINARY_PATH)

# Setup the entry state and stack frame
s = p.factory.full_init_state(addr=0x1400013B1)
s.regs.rbp = s.regs.rsp
s.regs.rsp = s.regs.rsp - 0x70

# Create the symbolic password buffer and add constraints
password_chars = [claripy.BVS('pass_%d' % i, 8) for i in range(56)]
password = claripy.Concat(*password_chars)
s.memory.store(s.regs.rbp - 0x50, password)

for c in password.chop(8):
    s.add_constraints(c >= '\x21') # '!'
    s.add_constraints(c <= '\x7e') # '~'

# Create the simulation manager
simgr = p.factory.simgr(s)

# Explore for solutions
print('Searching...')
simgr.explore(find=0x140001AC3, avoid=0x140001AC4)

if len(simgr.stashes['found']) != 0:
  print('Password found: ', simgr.stashes['found'][0].solver.eval(password, cast_to=bytes).decode())
else:
  print('Password not found')

```

Running the solver:
```
$ source  ~/.local/pipx/venvs/angr/bin/activate
$ python3 solver.py
...
Solving...
...
Password: DWPQTV@PS\@H"PUHVHPHPQ@@SX@PPHHYHHWP@PQQ@SPBHCHHRHPWPPPN
```

We can run it multiple times and keep getting others too:
```
PWPQTV@P@@@P"PUPVPPPPQ@/SAOPP0P@P0W0@PQQ@SPAP!P02PPW00PB
0WPQTV@P@@O0"PUHVPPPP1OO3BOPPPPCHPWP@PQ1@SP&P"PPRHPWPPP@
HWPQTV@P@J@H"PUHVHPHPQ@@SG@PPHHGHHWP@PQQ@SPYHCHHRHPWPPP^
```

Trying them out:
```
Enter name of medicine for Bobby!!DWPQTV@PS\@H"PUHVHPHPQ@@SX@PPHHYHHWP@PQQ@SPBHCHHRHPWPPPN


 00000
0     0
0 0 0 0
0  0  0
0     0
0 000 0
0     0
 00000
Thanks! Bobby now is cured!
```

Nice!

QED
