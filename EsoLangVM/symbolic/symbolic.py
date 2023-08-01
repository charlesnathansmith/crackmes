#!/usr/bin/python3
from enum import Enum
import sys
import re

# Operand type
class optype(Enum):
    reg = 0     # register
    mem = 1     # memory
    num = 2     # numeric literal
    str = 3     # named input operands

# Instruction class
class ins:
    def ishex(self, s):
        return not re.search(r"[^A-F0-9]", s)
    
    def __init__(self, mnemonic, dst, src):
        self.mnemonic = mnemonic
        self.output = False
        
        if dst[:4] == '[esi':
            self.dst_type = optype.mem
            self.dst = dst[5:8]
        else:
            self.dst_type = optype.reg
            self.dst = dst

        if src[:4] == '[esi':
            self.src_type = optype.mem
            self.src = src[5:8]
        elif self.ishex(src):
            self.src_type = optype.num
            self.src = int(src, 16)
        else:
            self.src_type = optype.reg
            self.src = src

# Value store class
class vstore:
    def __init__(self, terms = list(), offset = 0):
        self.terms = terms
        self.offset = offset

    def add(self, terms, offset = 0):
        self.terms = self.terms + terms
        self.offset += offset

    def sub(self, offset):
        self.offset -= offset

    def clear(self):
        self.terms = []
        self.offset = 0

    def str(self):
        ret = ' + '.join(self.terms)

        if self.offset != 0:
            if len(self.terms):
                ret += ' + ' + str(self.offset) if self.offset > 0 else ' - ' + str(-self.offset)
            else:
                ret += str(self.offset)

        return ret

# Register dictionary
reg_names = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp']
reg_vals = { name:vstore() for name in reg_names }

# Instruction listing
ins_valid = ['add', 'and', 'mov', 'sub']
ins_list = []
unprocessed = []

# Input paramaters and output results
params = dict()
outputs = dict()

# Peephole optimization
def peephole(ins_list):
    for i in ins_list:
        if i.mnemonic == 'and' and i.src == 0xffffff:
            i.mnemonic = 'nop'
            i.src = i.dst = i.dst_type = i.src_type = ''
        elif i.mnemonic == 'add' and i.src_type == optype.num and i.src & 0x800000:
            i.mnemonic = 'sub'
            i.src = 0x1000000 - i.src

# Label input registers
def mark_inputs(ins_list, params):
    assigned = set()
    cur = 0

    for i in ins_list:
        if i.src_type == optype.reg and i.src not in assigned:
            i.src_type = optype.str
            
            if i.src in params:
                i.src = params[i.src]
            else:
                pname = f"param_{cur}"
                reg_vals[i.src].add([pname])
                params[i.src] = pname
                i.src = pname
                cur += 1

        if i.dst_type == optype.reg:
            assigned.add(i.dst)

# Mark output registers
def mark_outputs(ins_list, outputs):
    cur = 0

    for i in reversed(ins_list):
        if i.dst_type == optype.reg and i.dst not in outputs:
            i.output = True

def resolve_mem(reg):
    return f"esi[{reg_vals[reg].str()}]"

# Parse instruction listing with constant folding
def parse_listing(ins_list):
    mem_dict = dict()
    
    for i in ins_list:
        # dst is a register
        if i.dst_type == optype.reg:
            if i.mnemonic == 'mov':
                reg_vals[i.dst].clear()

            if i.mnemonic == 'mov' or i.mnemonic == 'add':
                if i.src_type == optype.reg:
                    reg_vals[i.dst].add(reg_vals[i.src].terms, reg_vals[i.src].offset)
                elif i.src_type == optype.str:
                    reg_vals[i.dst].add([i.src])
                elif i.src_type == optype.mem:
                    mem_term = resolve_mem(i.src)

                    # Memory folding during reg assignment
                    if mem_term in mem_dict:
                        mem_term = mem_dict[mem_term]
                    
                    reg_vals[i.dst].add([mem_term])
                else:
                    reg_vals[i.dst].add([], i.src)  # number source

            if i.mnemonic == 'sub' and i.src_type == optype.num:
                reg_vals[i.dst].sub(i.src)

            if i.output:
                outputs[f"out({i.dst})"] = reg_vals[i.dst].str()
        
        # dst is memory
        elif i.dst_type == optype.mem:
            if i.src_type == optype.reg:
                mem_pair = [f"{resolve_mem(i.dst)}", f"{reg_vals[i.src].str()}"]
            elif i.src_type == optype.str:
                mem_pair = [f"{resolve_mem(i.dst)}", f"{i.src}"]

            # Memory folding during memory assignment
            if mem_pair[1] in mem_dict:
                mem_pair[1] = mem_dict[mem_pair[1]]

            mem_dict[mem_pair[0]] = mem_pair[1]
            print(f"{mem_pair[0]} = {mem_pair[1]}")

# Print instruction listing
def print_listing(ins_list):
    for i in ins_list:
        if i.mnemonic != 'nop':
            dst = f"esi[{i.dst}]," if i.dst_type == optype.mem else f"{i.dst},     "
            dst += '     ' if dst[:3] != 'out' else ''
            src = f"esi[{i.src}]" if i.src_type == optype.mem else i.src
            print(f"{i.mnemonic}\t{dst}{src}")

    print('\nUnprocessed:')

    for line in unprocessed:
        print(line)

# main

if len(sys.argv) != 2:
    print("symbolic.py file\n")
    exit()

# Initial instruction loading
with open(sys.argv[1]) as file:
    processing = True
    
    for line in file:
        ins_inf = re.search('LOAD:[0-9A-F]{8}\s*([a-z]{3})\s*(.*), ([a-gi-zA-F0-9\[\]+*]*)', line)

        if processing:
            if ins_inf and ins_inf[1] in ins_valid:
                ins_list.append(ins(ins_inf[1], ins_inf[2], ins_inf[3]))
            else:
                processing = False
                
        if not processing:
            unprocessed.append(line.strip())
                

peephole(ins_list)
mark_inputs(ins_list, params)
mark_outputs(ins_list, outputs)

print("\nInputs:")
for key in params:
    print(f"{params[key]}: {key}")

print("\nParsed:")
parse_listing(ins_list)

print("\nOutputs:")
for key, value in outputs.items():
        print(f"{key}: {value}")

print('\nUnprocessed:')

for line in unprocessed:
    print(line)
