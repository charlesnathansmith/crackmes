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
