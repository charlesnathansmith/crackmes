#!/usr/bin/python3
import sys

graph = dict()
ordered_macros = []

if len(sys.argv) == 2:
    name = sys.argv[1]
else:
    name = input('Filename: ')

with open(name) as file:
    last = ''
    
    for line in file:
        macro = line.rstrip()
        
        if macro not in graph:
            graph[macro] = dict()
            ordered_macros.append(macro)

        if last != '':
            if macro not in graph[last]:
                graph[last][macro] = 0
                
            graph[last][macro] += 1

        last = macro

print('digraph cfg {')

#for src, child in graph.items():
    #for dst, count in child.items():
    #    print(f'{src} -> {dst} [ label = "{count}" ]')

for src in ordered_macros:
    for dst, count in graph[src].items():
        print(f'{src} -> {dst} [ label = "{count}" ]')

print('}')
