# solver.py
import angr, claripy

BINARY_PATH = './patched.exe'

# Create the project
p = angr.Project(BINARY_PATH)

# Setup the entry state and stack frame
s = p.factory.full_init_state(addr=0x1400013B1)  # start after return from vfscanf stub
s.regs.rbp = s.regs.rsp
s.regs.rsp = s.regs.rsp - 0x70

# Create the symbolic password buffer and add constraints
password_chars = [claripy.BVS('pass_%d' % i, 8) for i in range(56)]
password = claripy.Concat(*password_chars)
s.memory.store(s.regs.rbp - 0x50, password)

for c in password.chop(8):
    s.add_constraints(c >= '\x21') # '!'
    s.add_constraints(c <= '\x7e') # '~'

print("Solving...")

# Create the simulation manager
simgr = p.factory.simgr(s)

# Explore for solutions
simgr.explore(find=0x140001AC3, avoid=0x140001AC4)

if len(simgr.stashes['found']) != 0:
	print('Password: ', simgr.stashes['found'][0].solver.eval(password, cast_to=bytes).decode())
else:
	print('Password not found')
