# Control-Flow Graph generator

Turns macro lists from execution traces into DOT-format graphs
Edges are labeled with how many times they are traversed during execution

```
$ sudo apt install graphviz
$ python3 macros.txt > macros.dot
$ dot -tSvg macros.dot > macros.svg
```
