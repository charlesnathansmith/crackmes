pufferisadev's lisence_checker
https://crackmes.one/crackme/64c8b272b25df8732eebc2a6

# Overview

This is a follow-up to my first solution which will explore the author's suggeestion that we try a time-based attack against the key.

For that reason, I will omit some of the initial setup and analysis and focus only on what's relevant to this particular attack.

# Key generation algorithm

Ghidra does a faily good job at decompiling the generate_key function we are interested in:
```
undefined * _generate_key(void)

{
  int iVar1;
  time_t tVar2;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  int local_c;
  
  tVar2 = _time((time_t *)0x0);
  _srand((uint)tVar2);
  for (local_c = 0; local_c < 5; local_c = local_c + 1) {
    iVar1 = _rand();
    (&_generate_key.key)[local_c] = (char)(iVar1 % 0x1a) + 'A';
  }
  DAT_100008055 = 0x2d;
  for (local_10 = 6; local_10 < 0xb; local_10 = local_10 + 1) {
    iVar1 = _rand();
    (&_generate_key.key)[local_10] = (char)(iVar1 % 10) + '0';
  }
  DAT_10000805b = 0x2d;
  for (local_14 = 0xc; local_14 < 0x11; local_14 = local_14 + 1) {
    iVar1 = _rand();
    (&_generate_key.key)[local_14] = (char)(iVar1 % 0x1a) + 'A';
  }
  DAT_100008061 = 0x2d;
  for (local_18 = 0x12; local_18 < 0x17; local_18 = local_18 + 1) {
    iVar1 = _rand();
    (&_generate_key.key)[local_18] = (char)(iVar1 % 10) + '0';
  }
  DAT_100008067 = 0x2d;
  for (local_1c = 0x18; local_1c < 0x1d; local_1c = local_1c + 1) {
    iVar1 = _rand();
    (&_generate_key.key)[local_1c] = (char)(iVar1 % 0x1a) + 'A';
  }
  DAT_10000806d = 0;
  return &_generate_key.key;
}
```

Let's break down what's happening here.

The call to time() returns the current system time (in seconds since Jan 1, 1970 00:00:00 UTC -- the so-called "epoch".)
This value is passed to srand(), which seeds the random-number generator (RNG).
Then repeated calls to rand() are used to get pseudo-random numbers used to construct a key that looks like this:
```
AAAAA-00000-AAAAA-00000-AAAAA
```

Where each A is replaced by (rand() % 26) + 'A' and each 0 is replaced with (rand() % 10) + '0'

Since seeding the RNG with the same value will always return the same results in subsequent calls to rand(),  
if we can use the same seed as the target, we can generate the same key that it does.

To accomplish this, we need to launch the target and try to obtain the system time within a second of when it does.
Since this call happens early in the target, this can generally be accomplished by doing one immediately after the other.

This may fail occassionally when the calls straddle a second tick.
Retrying a few times should eventually succeed.

On a very slow system where the target takes some time to load, it may be necessary to adjust the seed by an appropriate amount, 
though this is fairly unlikely on modern hardware (it works fine running in a VM for me.)

# Final attack

Here is the final time-based attack, written in C to keep our and the target's calls to time() as close as possible.
The target is launched before we generate the key, to possibly give some leeway for load times, but this shouldn't generally matter.

timing.c
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void generate_key(char* key, size_t seed)
{
	size_t pos = 0;
	
	printf("Seed: %.8X\n", (unsigned int) seed);
	srand(seed);
	
	for ( ; pos < 5; pos++ )
		key[pos] = (rand() % 0x1a) + 'A';
	
	for ( pos++; pos < 11; pos++ )
		key[pos] = (rand() % 10) + '0';
	
	for (pos++; pos < 17; pos++ )
		key[pos] = (rand() % 0x1a) + 'A';
	
	for (pos++; pos < 23; pos++ )
		key[pos] = (rand() % 10) + '0';
	
	for (pos++; pos < 29; pos++ )
		key[pos] = (rand() % 0x1a) + 'A';
}

const char usage[] =
"%s target\n\n"
"target\tCommand to launch the target\n\n"
"Eg: %s \"./ld-mac main\"\n";

int main (int argc, char** argv)
{
	char key[] = "AAAAA-00000-AAAAA-00000-AAAAA", line_in[1024];
	FILE *target;
	
	if (argc < 2)
	{
		printf(usage, argv[0], argv[0]);
		return -1;
	}
	
	printf("Launching timing attack against \"%s\"...\n", argv[1]);
	
	// Launch target program
	if (!(target = popen(argv[1], "w")))
	{
		printf("Unable to launch target: %s\n", argv[1]);
		return -1;
	}
	
	// Generate key based on current system time
	// Ideally we get the same time as the target
	// If the attack fails, try it a few times,
	// or adjust the seed +- 1 (or further for a very slow system)
	generate_key(key, (size_t) time(0));
	printf("Key: %s\n\n", key);

	// Enter the key
	fputs(key, target);
	
	pclose(target);
	return 0;
}
```

Result:
```
$ gcc -o timing timing.c
$ ./timing "./ld-mac ./main"
Launching timing attack against "./ld-mac ./main"...
Seed: 64DD387B
Key: RUBJS-59992-TNCKC-73958-ICQRV

Enter the key: Success! The key was correct.
```

QED
