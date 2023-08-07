# (Partially) lifting ELVM macros

The codebase this needs to work on is extremely limited, and this isn't designed to generalize at all,
just to meet our needs for this one project.

This solution is custom tailored to the executable that came with the challenge,
and may or may not work with other ELVM-compiled programs.

# Assumptions and requirements

Each macro receives some inputs stored in registers, including esi which is a pointer to a large int table that doesn't change.
Among the inputs are indices used to reference into the table.
Values are read from and written to the table, with some basic math sometimes performed in between.
We want to boil each macro down to its changes to the table, and it's outputs (registers that are left changed on exit.)

We want the table indexing to be relative to the inputs.
If idx1 is passed into the macro via edi, and we then have:

```
mov edx, edi
add edx, 1
mov eax, [esi+edx*4]
```

Then we want to keep up with that as "eax = esi[idx1 + 1]".

Unless eax is an output register, as defined above, then we only care about where it goes.
If the next instructions look like:

```
add edi, 2
mov [esi+edi*4], eax
```

Then we ultimately want this folded into "esi[idx + 2] = esi[idx1 + 1]".
Also of note here is that even though idx1 was passed in through edi, and edi is being altered here,
we still want to keep up with the offset relative to the original input idx1.

We can accomplish this by treating each register as a set of components that make up its value,
some of which are irreducible.

If we restart with edi = idx1 again, and we have:
```
01:		mov edx, edi
02:		add edx, 2
03:		mov eax, [esi+edx*4]
04:		add edx, eax
05:		add edx, 3
```

After line 1, edx = { idx1 }
After line 2, edx = { idx1, 1}
idx1 is irreducible, so these can't be folded together.

After line 3, eax = { mem({ idx1, 1}) }
Since all memory reads and writes involve table offsets, these references can just be a special type of irreducible term.

After line 4, edx = { idx1, 1, mem({ idx1, 1})}
This cannot be further reduced

After line 5, edx = { idx1, 1, mem({ idx1, 1}), 3}
All the reducible terms can be combined here, leaving edx = { idx1, 4, mem({ idx1, 1}) }

It's straightforward enough on paper.
In practice each of these terms will have to be instances of some kind of object,
that can be nested and recursively reduce themselves after updates (constant folding.)

It would probably be a good idea to account for memory permanence.
For example:

```
mov	eax, [esi+edx*4]
mov ebx, eax
sub eax, [esi+edx*4]
```
vs
```
mov eax, [esi+edx*4]
mov [esi+edx*4], ebx
sub eax, [esi+edx*4]
```

In the first case, the memory value is unchanged and should cancel out in eax, but in the second case it shouldn't.
This raises another issue with something like:

```
mov eax, [esi+index*4]
mov [esi+index*4], ebx
mov ecx, [esi+index*4]
mov [esi+edi*4], ecx
```

We need to be cognizant of which value from mem({ index }) is being written to mem( { edi } ) since it has different values at different times.
Since we're doing fairly localized folding, and are just trying to produce a new listing that's easier to follow,
rather than producing some holistic execution map like we would need for something like constraint solving, we can probably not worry too much about this.
As long as we print out memory reads and writes as we encounter them, it should be clear when stored values have changed in between operations.

We can also do some peephole optimization.
The following is really common:

```
add edx, 0FFFFFFh
and edx, 0FFFFFFh
```

The engine just operates on 48-bit values.
This is equivalent to "sub edx, 1" and we can go through replacing pairs like this with the corresponding instructions.
If we see a bare "and edx, 0FFFFFFh" instruction, we can probably safely ignore it and still produce accurate output.

The whole thing is going to be pretty janky and inefficient, but the macros follow a simple enough pattern that it should be just doable.
See (lifting.py) for what I came up with.

# Results

```
$ python3 lifting.py macros/688.txt

Inputs:
in(edi): edi
in(eax): eax
in(ebp): ebp

Parsed:
0010FB0A	mov	edx,	      in(edi)
0010FB0C	sub	edx,	      1
0010FB18	mov	esi[edx],     in(eax)	;esi(in(edi) - 1) = in(eax)
0010FB1B	mov	edi,	      edx
0010FB1D	mov	ebx,	      in(ebp)
0010FB1F	add	ebx,	      2
0010FB2B	mov	eax,	      esi[ebx]
0010FB2E	mov	edx,	      edi
0010FB30	sub	edx,	      1
0010FB3C	mov	esi[edx],     ebx	;esi(in(edi) - 2) = in(ebp) + 2
0010FB3F	mov	edi,	      edx
0010FB41	mov	edx,	      edi
0010FB43	sub	edx,	      1
0010FB4F	mov	esi[edx],     eax	;esi(in(edi) - 3) = esi(in(ebp) + 2)
0010FB52	mov	edi,	      edx
0010FB54	mov	ebx,	      in(ebp)
0010FB56	sub	ebx,	      1
0010FB62	mov	eax,	      esi[ebx]
0010FB65	mov	edx,	      edi
0010FB67	sub	edx,	      1
0010FB73	mov	esi[edx],     eax	;esi(in(edi) - 4) = esi(in(ebp) - 1)
0010FB76	mov	edi,	      edx
0010FB78	add	eax,	      1
0010FB84	mov	ebx,	      in(ebp)
0010FB86	sub	ebx,	      1
0010FB92	mov	esi[ebx],     eax	;esi(in(ebp) - 1) = esi(in(ebp) - 1) + 1
0010FB95	mov	eax,	      esi[edi]
0010FB98	add	edi,	      1
0010FBA4	mov	ebx,	      eax
0010FBA6	mov	eax,	      esi[edi]
0010FBA9	add	edi,	      1
0010FBB5	add	eax,	      ebx
0010FBBD	mov	ecx,	      eax
0010FBBF	mov	eax,	      esi[edi]
0010FBC2	add	edi,	      1
0010FBCE	mov	ebx,	      eax
0010FBD0	mov	eax,	      ecx
0010FBD2	mov	ecx,	      eax
0010FBD4	mov	eax,	      esi[edi]
0010FBD7	mov	ebx,	      eax
0010FBD9	mov	eax,	      ecx
0010FBDB	mov	esi[eax],     ebx	;esi(esi(in(ebp) + 2) + esi(in(ebp) - 1)) = in(eax)
0010FBDE	mov	eax,	      esi[edi]
0010FBE1	add	edi,	      1
0010FBED	mov	edx,	      edi
0010FBEF	sub	edx,	      1
0010FBFB	mov	esi[edx],     eax	;esi(in(edi) - 1) = in(eax)
0010FBFE	mov	edi,	      edx
0010FC00	mov	eax,	      10
0010FC05	mov	ebx,	      eax
0010FC07	mov	eax,	      esi[edi]
0010FC0A	add	edi,	      1

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

Not too bad.
Compare it to the manual analysis in 688_manual.txt to see we get the same results.

We can easily start seeing some structure in the reduced output, like eg:

```
esi(param_0 - 4) = esi(param_2 - 1)
esi(param_2 - 1) = esi(param_2 - 1) + 1
```

'esi(param_0 - 4)' gets assigned what appears to be a counter, then the counter gets incremented.

I've left the comparisons unprocessed at the end for now and built it just to help process the tedious table operations.

We can start piecing together the reduced versions of the macros and trying to analyze them statically,
and can make some progress that way, but it would help to get a full trace where we can see what all of these values are.

