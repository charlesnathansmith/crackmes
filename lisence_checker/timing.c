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
