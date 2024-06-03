# Never gonna run around and reverse you

## First look

We are given a `hash` file consisting of a hexadecimal string and a
`hasher` file that appears to be the compiled program that produced the
`hash`.

For futher analysis we run `strings hasher` and confirm that it contains
strings that indicate a C-like origin.

## Decompilation

We decompile the program using BinaryNinja on the
[dogbolt](https://dogbolt.org) decompiler explorer:

``` c
int32_t main(int32_t argc, char** argv, char** envp)
{
    if (argc <= 1)
    {
        printf("Please provide a flag as an argu…");
        exit(1);
        /* no return */
    }
    char* rax_2 = argv[1];
    int32_t rax_4 = strlen(rax_2);
    void* rax_8 = malloc((rax_4 + 2));
    strcpy((rax_8 + 1), rax_2);
    for (int32_t i = 1; rax_4 >= i; i = (i + 1))
    {
        *(rax_8 + i) = (*(rax_8 + i) ^ *(rax_8 + (i - 1)));
        printf("%02x", *(rax_8 + i));
    }
    putchar(0xa);
    return 0;
}
```

Further clean-up of the code is done manually in order to better
understand the used hashing scheme:

``` c
void hash(char *input)
{
    int input_len = strlen(input);
    void* buffer = malloc(input_len + 2);
    strcpy((buffer + 1), input_len);
    for (int i = 1; input_len >= i; i += 1)
    {
        buffer[i] = buffer[i] ^ buffer[i - 1];
        printf("%02x", buffer[i]);
    }
    printf('\n');
}
```

## Exploit

The exploit can now simply be achieved by reversing the given hash
function. We (ab)use the fact that XOR is a reversible operation.
Therefore, the following Python script decodes the provided `hash`.

``` python
hash = "...<hash>..."
hash_bytes = b"\0" + bytes.fromhex(hash)

for i in range(1, len(hash_bytes)):
    print(chr(hash_bytes[i] ^ hash_bytes[i - 1]), end="")
```

``` bash
> GPNCTF{...}
```
