#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// XTEA decryption
// https://en.wikipedia.org/wiki/XTEA
void xtea_decrypt(uint32_t v[2], uint32_t const key[4], uint32_t num_rounds )
{
    uint32_t v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * num_rounds;

    for (uint32_t i = 0; i < num_rounds; i++)
    {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0; v[1] = v1;
}

int error(const char* msg)
{
    puts(msg);
    return -1;
}

int main(int argc, char** argv)
{
    //const uint32_t key[4] = { 0x2f36322f, 0x3a523838, 0x1d384645, 0x4080362a };
    uint32_t key[4] = { 0 };

    if (argc != 7)
    {
        puts("xteadec in_file out_file K0 K1 K2 K3");
        return error("Key values Kx are each 32-bit hex integers");
    }

    // Open input and output files
    FILE *in = fopen(argv[1], "rb"), *out = fopen(argv[2], "wb");

    if (!in)
        return error("Couldn't open input file");
    if (!out)
        return error("Couldn't open output file");

    // Set the decryption key
    for (size_t i = 0; i < 4; i++)
        key[i] = strtol(argv[i + 3], 0, 16);

    // Decrypt the file
    uint32_t data[2] = { 0 };

    while (fread(data, sizeof(uint32_t), 2, in) == 2)
    {
        xtea_decrypt(data, key, 0x40);
        if (fwrite(data, sizeof(uint32_t), 2, out) != 2)
        {
            puts("Write error");
            break;
        }
    }

    fclose(in);
    fclose(out);
    return 0;
}
