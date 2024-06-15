# Archventuretime

Archventuretime is a reversing challenge, where you have to obtain a license-key.

## First look
The challenge consists of binary and a Dockerfile. The Dockerfile installs various QEMU packages on an ubuntu system and then starts the binary. 
After starting the docker you are prompted with `Enter license key> `, so I entered a few random chars and, surprise, `[WARNING] Invalid format!`
 (Note: i changed the flag in `docker run -t` to `docker run -ti` to get inputs working).

# The main binary
So let's look at the included binary `chal`:
```
> file chal
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, [...] , for GNU/Linux 3.2.0, stripped
```
Unfortunately `chal` is stripped so reversing it will be a bit harder. So let's get to work and decompile `chal` with ghidra. If we search for the `Enter license key> `, we find the following functions. I added some comments to it, with ideas I got from the initial look.
```c
undefined8 FUN_00101c48(void) {
  /* [...] <- variable definitions removed for readability */
  
  // read liscence key up to length 24d, and remove new lines
  printf("Enter license key> ");
  fgets((char *)&local_48,0x18,stdin);
  sVar1 = strcspn((char *)&local_48,"\n");
  *(undefined *)((long)&local_48 + sVar1) = 0;

  // call some function with the liscence key, not sure what it does yet
  FUN_001014a9(&local_48);
  
  // remove every 6th char from the key and save the result in local_28
  local_50 = 0;
  for (local_4c = 0; local_4c < 0x17; local_4c = local_4c  + 1) {
    if ((local_4c + 1) % 6 == 0) {
      local_50 = local_50 + 1;
    }
    else {
      *(undefined *)((long)&local_28 + (long)(local_4c - l ocal_50)) =
           *(undefined *)((long)&local_48 + (long)local_4c) ;
    }
  }

  // call a function, with the stripped liscence key
  FUN_001015dc(&local_28);

  // call a function with the liscence key
  FUN_00101920(&local_48);
  
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return * /
    __stack_chk_fail();
  }
  return 0;
}
```
We saw that the functions reads the key and then calls three different functions with it. So let's call the function `readKey` and take a look what the first called function does. We already know, that it takes the license-key as an argument, so I already renamed the parameter and added comments:
```c

void FUN_001014a9(char *key) {
  size_t sVar1;
  ushort **ppuVar2;
  int local_c;
  
  // ensure that the key length is >= 23d, else print a warning and exit
  // since we read keys with length up to 24d we know that the liscence key must exactly be 24d 
  // chars long
  sVar1 = strlen(key);
  if (sVar1 < 0x17) {
    puts(PTR_s_[WARNING]_Invalid_format!_0012a010) ;
                    /* WARNING: Subroutine does not return * /
    exit(1);
  }
  // loop through the key
  local_c = 0;
  do {
    if (0x16 < local_c) {
      return;
    }
    // check that every 6th char is a '-' 
    if ((local_c + 1) % 6 == 0) {
      if (key[local_c] != '-') {
        puts(PTR_s_[WARNING]_Invalid_format!_0012a01 0);
                    /* WARNING: Subroutine does not return * /
        exit(1);
      }
    }
    // check that every other char is uppercase and alphanumeric, if this is not the case
    // print a warning and exit the programm
    else {
      // __ctype_b_loc() returns a struct with informations about the char
      ppuVar2 = __ctype_b_loc();
      // char is not upper case?
      if (((*ppuVar2)[key[local_c]] & 0x800) == 0) {
        ppuVar2 = __ctype_b_loc();
        // char is not a number?
        if (((*ppuVar2)[key[local_c]] & 0x100) == 0) {
          puts(PTR_s_[WARNING]_Invalid_format!_0012a0 10);
                    /* WARNING: Subroutine does not return * /
          exit(1);
        }
      }
    }
    local_c = local_c + 1;
  } while(true);
}
```
So the method seems to check that the license-key is in the format "XXXXX-XXXXX-XXXXX-XXXXX", with X being an alphanumeric char. So let's call the method `checkFormat` and construct a key and input it into the binary.

```
> ./chal
Enter license key> 12345-ABCDE-12345-ABCDE
[ERROR] Invalid license key!
```
Yaaay 🎉, a different error message. Since the error message isn't printed in `checkFormat` our key has the correct format now and we can continue to the next method call in the `readKey` function. Again, I already renamed the parameter of the function and added comments:

```c

void FUN_001015dc(char *strippedKey) {
   /* [...] <- variable definitions removed for readability */

  // change working directory to '/tmp'
  chdir("/tmp");
  
  // loop with 4 iterations
  for (local_d0 = 0; local_d0 < 4; local_d0 = local_d0 + 1 ) {
    lVar3 = (long)(int)local_d0;
    puVar1 = (&PTR_s_qemu-riscv64_-L_/usr/riscv64-li n_00129c80)[lVar3 * 3];
    __buf = (&PTR_DAT_00129c88)[lVar3 * 3];
    __n = *(size_t *)(&DAT_00129c90 + lVar3 * 0x18);
    local_a4 = 0x5858586b63656863;
    local_9c = 0x585858;
    iVar2 = mkstemp((char *)&local_a4);
    write(iVar2,__buf,__n);
    close(iVar2);
    chmod((char *)&local_a4,0x1c0);
    snprintf((char *)&local_98,0x80,"%s %s %s",puVar1, &local_a4,strippedKey);
    iVar2 = system((char *)&local_98);
    if (iVar2 != 0) {
      remove((char *)&local_a4);
      puts(PTR_s_[ERROR]_Invalid_license_key!_0012a0 18);
                    /* WARNING: Subroutine does not return * /
      exit(1);
    }
    remove((char *)&local_a4);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return * /
    __stack_chk_fail();
  }
  return;
}
```
Ok a lot is happening here, let's give names to the variables:
```c
void FUN_001015dc(char *strippedKey) {

  /* [...] <- variable definitions removed for readability */

  // change working directory to '/tmp'
  chdir("/tmp");

  // loop with 4 iterations
  for (idx = 0; idx < 4; idx = idx + 1) {
    idx_ = (long)(int)idx;
  // command in the form of qemu-riscv64 -L /usr/riscv64-linux-gnu, the architecture changes in every iteration */
    commandPrefix = (&PTR_s_qemu-riscv64_-L_/usr/r iscv64-lin_00129c80)[idx_ * 3];

	// read raw
    __buf = (&PTR_DAT_00129c88)[idx_ * 3];
    __n = *(size_t *)(&DAT_00129c90 + idx_ * 0x18);

	// create a file with name checkXXXXXX, with X being random chars 
	// and write __buf into it
    filename = 0x5858586b63656863;
    local_9c = 0x585858;
    fileDescriptor = mkstemp((char *)&filename);
    write(fileDescriptor,__buf,__n);
    close(fileDescriptor);

	// make the file executable
    chmod((char *)&filename,0x1c0);

	// execute the command qemu-riscv64 -L <architecture> filename strippedKey
    snprintf((char *)&local_98,0x80,"%s %s %s",commandPrefix,&filename,strippedKey);
    status = system((char *)&local_98);

	// if the previously executed command returns an error, print an error and exit
	
    if (status != 0) {
      // deltete the file
      remove((char *)&filename);
      puts(PTR_s_[ERROR]_Invalid_license_key!_0012a0 18);
                    /* WARNING: Subroutine does not return * /
      exit(1);
    }
    // delete the file
    remove((char *)&filenameTemplate);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return * /
    __stack_chk_fail();
  }
  return;
}
```
The function creates 4 new binaries, executes them with the license-key as an argument. If one binary fails, an error is printed and the `chal` exists, so we call the function `checkWithBinaries`. Before we dive deeper in the newly created binaries, let's take a quick look at the third function call in the `readKey` function:
```c
void FUN_00101920(void *param_1) {
    /* [...] <- variable definitions removed for readability */

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts(PTR_s_[CORRECT]_License_key_validated_001 2a020);
  printf("Decrypting product");
  fflush(stdout);
  for (local_130 = 0; local_130 < 3; local_130 = local_13 0 + 1) {
    sleep(1);
    putc(0x2e,stdout);
    fflush(stdout);
  }
  putc(10,stdout);
  putc(10,stdout);
  fflush(stdout);

/* [...] <- variable definitions removed for readability */


  // use AES to decrypt the Flag with the key
  iVar1 = FUN_00101828(&local_e8,0x50,&local_108,&l ocal_118,&local_98);
  *(undefined *)((long)&local_98 + (long)iVar1) = 0;
  puts(
      "Welcome to GPN CTF 2024!\n\n            ========= ==            \n        ===================        \n     -= ======================-     \n    ============ ===============    \n  -===============-==== =========-  \n  ===========::::::============= =  \n =============:=========::::====== \n==== ===========:::::::::::::=======\n===========::=-::: ::::::::::=======\n==========::::=-::::::::::========= \n=========::::::=-:-================\n====== ==::::::::=-:================\n ======::::::::::=-:== ============ \n  =====:::::::::::=-=============  \n  -=====:::::::::::=============-  \n    ========= ==================    \n     -================ =======-     \n        ===================        \n            ===========            \n\n"
      );
  puts((char *)&local_98);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return * /
    __stack_chk_fail();
  }
  return;
}
```
This function seems to decrypt the Flag with the license-key using the AES and print a nice message. As far as I can tell, the key decryption looks save. So we need to obtain the license-key by reversing the binaries created by the `checkWithBinaries` function.

## Four new binaries
At first, we actually need to obtain the binaries, which isn't trivial because the are instantly delted after their execution:
```c
void  checkWithBinaries(char  *strippedKey) {
    // [...]
	if  (status !=  0)  {  
		remove((char  *)&filename);
		puts(PTR_s_[ERROR]_Invalid_license_key!_0012a0 18); 
		exit(1); 
	}
	// [...]
}
```

 I can think of two good ways to achieve this:
* Debug `chal` with gdb and break right before `remove` gets called
* Patch the binary and change `remove` to `strlen` for example
 
I went with the second option, and created `chal_patched`,  executing it yields:
```
> ./chal_patched
Enter license key> 12345-ABCDE-12345-ABCDE
[ERROR] Invalid license key!
> ls /tmp | grep "check"
checkr5Rt4S
``` 
Voila, the first binary! Decompiling it with ghirda and searching a bit yields the following main function (I already renamed a few symbols):
```c
ulong main(int param_1,long param_2)

{
  undefined4 strLen;
  long check;
  ulong succ_;
  char *arg1;
  
  if (param_1 < 2) {
    succ_ = 1;
  }
  else {
    arg1 = *(char **)(param_2 + 8);
    strLen = getStrLen(arg1);
    sort(arg1,strLen);
    check = strcmp(arg1,"067889BBCKKMOPPUVWYY");
    if (check == 0) {
      succ_ = 0;
    }
    else {
      succ_ = 1;
    }
  }
  return succ_;
}
```
Sort is just a basic quicksort implementation. So the binary just checks if the inputed liscence-key consists of the same chars as the correct liscence key in arbitrary order. With this we know all chars of our Key `067889BBCKKMOPPUVWYY` and can construct a new key bypassing the first binary:
```
> rm /tmp/check*
> ./chal_patched 
Enter license key> 06788-9BBCK-KMOPP-UVWYY
[ERROR] Invalid license key!
> ls /tmp/ | grep check
checkHhOuNh
checkJRzpc8
```
Nice! Our second binary, lets also analyze it with ghidra (I already renamed a few symbols):
```c

undefined8 main(int param_1,long param_2) {

   /* [...] <- variable definitions removed for readability */
  
  if (param_1 < 2) {
    uVar1 = 1;
  }
  else {
    __s = *(char **)(param_2 + 8);
    strlen(__s);
    // loop through the key, split it in to 4 blocks of size 5
    for (local_24 = 0; local_24 < 4; local_24 = local_24 + 1) {
      local_20 = 0;
      local_1c = 0;
      for (local_18 = local_24 * 5; local_18 < (local_24 + 1) * 5; local_18 = local_18 + 1) {
       // check if the char is uppercase
       // if thats the case we add its value (ascii representation) and -0x41 to local_1c 
        ppuVar2 = __ctype_b_loc();
        if (((*ppuVar2)[__s[local_18]] & 0x800) == 0) {
          ppuVar2 = __ctype_b_loc();
          if (((*ppuVar2)[__s[local_18]] & 0x100) != 0) {
            local_1c = local_1c + __s[local_18] + -0x41;
          }
        }
        // check if the char is numeric
        // if thats the case we add its value and -0x30 to local_20
        else {
          local_20 = local_20 + __s[local_18] + -0x30;
        }
      }
      // check if the sum for every block matches some constant
      // numeric chars and uppercase chars are seperated into two diffrent sums
      if (local_20 != *(int *)(&DAT_00102010 + (long)loca l_24 * 4)) {
        return 1;
      }
      if (local_1c != *(int *)(&DAT_00102020 + (long)loca l_24 * 4)) {
        return 1;
      }
    }
    uVar1 = 0;
  }
  return uVar1;
}
```
So this method splits the Key into 4 Blocks of 5 and then sums the block seperatly for uppercase and numeric chars. For example:
```
Key: 06788-9BBCK-KMOPP-UVWYY (Note: the key is passed without the '-' to the binary)
Blocks:
06788 -> sumNumeric = 0 + 6 + 7 + 8, sumUppercase = 0
9BBCK -> sumNumeric = 9, sumUppercase = B + B + C + K = 1 + 1 + 2 + 10
KMOPP -> sumNumeric = 0, sumUppercase = K + M + O + P + P = 10 + 12 + 14 + 15
UVWYY -> sumNumeric = 0, sumUppercase = U + V + W + Y + Y = 20 + 21 + 22 + 24 + 34
```
Then the binary takes those sums and checks each sum against a constant in the data section. With that we can write a script, which given all possible letters (from the first binary) outputs every possible key (Note that this script generates some duplicates, but this won't be a problem):
```py
import itertools  
  
  
# the constants we got from the second binary  
num0 = 0  
num1 = 0x00000007  
num2 = 0x0000000E  
num3 = 0x00000011  
  
let0 = 0x0000003D  
let1 = 0x00000024  
let2 = 0x0000002C  
let3 = 0x00000032  
  
# all possbile letters and numbers (from the first binary)  
letters = list("BBCKKMOPPUVWYY")  
numbers = list("067889")  
  
  
def list_diff(l1, l2):  
    """  
 :return l1 without all elements in l2 """  lx1 = l1[:]  
    for i in l2:  
        if i in lx1:  
            lx1.remove(i)  
    return lx1  
  
  
def get_combinations_up_to_5(l):  
    result = []  
    for i in range(0, 6):  
        result += list(itertools.combinations(l, i))  
    return result  
  
  
def find_sets(l, k):  
    """  
 find sets up to length 5 which sum up to k """  result = []  
    combinations = get_combinations_up_to_5(l)  
    for i in combinations:  
        if sum(i) == k:  
            result.append(i)  
    return result  
  
  
def flatten(l):  
    result = []  
    for i in l:  
        if type(i) is list:  
            for j in i:  
                result.append(j)  
        else:  
            result.append(i)  
    return result  
  
  
def flatten_result(l):  
    result = []  
    for i in l:  
        result.append(flatten(i))  
    return result  
  
  
def combine(elem, l):  
    result = []  
    for i in l:  
        if i is list:  
            for j in i:  
                result.append([elem, j])  
        else:  
            result.append([elem, i])  
    return result  
  
  
def partition_subset_sum(l, sizes):  
    """  
 partitions l in to combinations up to length 5 which sum matches sizes[i] """  valid = find_sets(l, sizes[0])  
    if len(sizes) == 1:  
        return valid  
 result = []  
    for valid_set in valid:  
        new_l = list_diff(l, valid_set)  
        new_valid = partition_subset_sum(new_l, sizes[1:])  
        result += combine(valid_set, new_valid)  
  
    return flatten_result(result)  
  
  
def encode(l, n):  
    encoded = []  
    for i in l:  
        encoded.append(ord(i) - n)  
    return encoded  
  
  
def decode(l, n):  
    decoded = []  
    for i in l:  
        tuple_ = []  
        for j in i:  
            tuple_.append(chr(j + n))  
        decoded.append(tuple(tuple_))  
  
    return decoded  
  
  
number_subsets = [decode(i, 48) for i in partition_subset_sum(encode(numbers, 48), [num0, num1, num2, num3])]  
letter_subsets = [decode(i, 65) for i in partition_subset_sum(encode(letters, 65), [let0, let1, let2, let3])]
```
Lets add print statements and run the code
```py
for i in letter_subsets:  
    for j in number_subsets:  
        x0 = i[0] + j[0]  
        x1 = i[1] + j[1]  
        x2 = i[2] + j[2]  
        x3 = i[3] + j[3]  
        if len(x0) == 5 and len(x1) == 5 and len(x2) == 5 and len(x3) == 5:  
            print(x0, x1, x2, x3)
```
With that we can build a new liscence key, which sould get past the first and second binary:
```
[...]
('K', 'K', 'M', 'O', 'P') ('B', 'P', 'U', '0', '7') ('B', 'V', 'W', '6', '8') ('C', 'Y', 'Y', '8', '9')
```
Lets bring it into the right format:
```
KKMOP-BPU07-BVW68-CYY89
```
And check if it works:

```
> rm /tmp/check*
> ./chal_patched 
Enter license key> KKMOP-BPU07-BVW68-CYY89
[ERROR] Invalid license key!
> ls /tmp/ | grep check
checkiUZg6q
checklhvtqU
checktyOyll
```
Here we go, our third binary :). As always we put it into ghidra (I already renamed a few symbols)
```c

undefined4 .opd.FUN_1000074c(int argc,longlong arg s) {
  int len;
  char *alphaNumIndex;
  int notSucc;
  undefined4 uVar1;
  char *key;
  int idx;
  
  if (argc < 2) {
    uVar1 = 1;
  }
  else {
    key = *(char **)(args + 8);
    // strLen wraps strlen
    len = strLen(key);
    // loop through the key
    for (idx = 0; idx < len + -1; idx = idx + 1) {
      // get the index in the alphabet + numerbs in the key
      // AlphaNum points to ABCDEFGHIJKLMNOPQRSTUVWXYZ012345689
      // strChr wraps strchr
      alphaNumIndex._4_4_ = strChr(AlphaNum,key[idx]) ;
      
      // UNK_10000940 points to a array of intergers with only the last 8Bit set
      // So we have 36 sections of size 24.
      // 36 is the size of the alpahbet plus the numbers
      // we pass the start of the section (index by the current char) to charInRange and we 
      // also pass the next char into char in range
      notSucc = charInRange(&UNK_10000940 + (longlong)(alphaNumIndex._4_4_ - (int)AlphaNum) * 96,
                            key[(longlong)idx + 1],24);
      if (notSucc == 0) {
        return 1;
      }
    }
    uVar1 = 0;
  }
  return uVar1;
}

```
So we loop through the key, in `charInRange` we perform some sort of check and if returns 0 the program exits with an error. Next we examine `charInRange` (Symbols renamed):
```c

undefined4 charInRange(longlong prevCharAddr,int char,int x24) {
  int idx;
  
  idx = 0;
  while(true) {
    // x24 is always 24
    if (x24 <= idx) {
      // keep in mind 0 means error
      return 0;
    }
    if (char == *(int *)(prevCharAddr + (longlong)idx * 4) ) break;
    idx = idx + 1;
  }
  return 1;
}
```
`charInRange` checks if the next char is somwhere in the section. If that is not the case it returns an error. This is the next constraint for out liscence-key. Nice! The next python script. Lets start off by extracting the array out of the binary:
```py
integers = []
try:  
    with open("<pathToBinary>/third", "rb") as fin:  
        # 0x0000940 is the start address of the array
        # 0x00016C0 the end address
        fin.seek(0x0000940)  
        for i in range(int((0x00016C0 - 0x0000940) / 4)):  
            fin.read(3)  
            x = fin.read(1)  
            integers.append(x)  
  
        for i in range(0, len(integers), 24):  
            blocksOf24.append(integers[i:i + 24])  
except FileNotFoundError:  
    print("File 'third' not found.")  
    exit(1)
```
Let's also add some code to generate permutations of the previously generated blocks and check if they are within the constrains of the third binary:
```py
from itertools import combinations, permutations  
from second import letter_subsets, number_subsets
  
alphaNum = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")  
  
def getPermutations(l):  
    c = []  
    n = 5  
  for i in range(n - 1, n):  
        c.extend(permutations(l, i + 1))  
    return c  
  
def printAsKey(l):  
    for x in range(len(l)):  
        if (x + 1) % 5 == 0 and x != 19:  
            print(l[x] + "-")  
        else:  
            print(l[x])  
    print("\n")  
  
def getAsInput(l):  
    result = ""  
  for x in range(len(l)):  
        result += l[x]  
    return result  
  
def combineLists(l1, l2):  
    result = []  
    c00 = getPermutations(l1)  
    c1 = getPermutations(l2)  
    for xx in c00:  
        for y in c1:  
            result.append(list(xx) + list(y))  
    return result  
  
integers = []  
blocksOf24 = []  
  
try:  
    with open("third", "rb") as fin:  
        fin.seek(0x0000940)  
        for i in range(int((0x00016C0 - 0x0000940) / 4)):  
            fin.read(3)  
            x = fin.read(1)  
            integers.append(x)  
  
        for i in range(0, len(integers), 24):  
            blocksOf24.append(integers[i:i + 24])  
except FileNotFoundError:  
    print("File 'third' not found.")  
    exit(1)  
  
def checkRule(chr, nextChr):  
    index = alphaNum.index(str(chr))  
    block = blocksOf24[index]  
    if nextChr.encode() in block:  
        return True  
 else:  
        return False  
  
possibleCombinations = []  
  
for pN in number_subsets:  
    for pL in letter_subsets:  
        pC = [pN[0] + pL[0], pN[1] + pL[1], pN[2] + pL[2], pN[3] + pL[3]]  
        continueFlag = False  
 for x in pC:  
            if len(x) != 5:  
                continueFlag = True  
 break if continueFlag:  
            continue  
  possibleCombinations.append(pC)  
  
def check(permutations):  
    result = []  
    for possibility in permutations:  
        appendFlag = True  
 for i in range(4):  
            if not checkRule(possibility[i], possibility[i + 1]):  
                appendFlag = False  
 break if appendFlag:  
            result.append(possibility)  
    return result  
  
def checkBordersAndCombine(l1, l2):  
    result = []  
    for xx in l1:  
        for y in l2:  
            if len(y) == 10:  
                # this condition will make sense after we saw the fourth binary
                if not (y[8] == "8" and y[7] == "M" and y[5] == "Y"):  
                    continue  
 if checkRule(xx[-1], y[0]):  
                result.append(xx + y)  
    return result  
  
allCombinations = []  
for pC in possibleCombinations:  
    firstPermutations = check(getPermutations(pC[0]))  
    secondPermutations = check(getPermutations(pC[1]))  
    thirdPermutations = check(getPermutations(pC[2]))  
    fourthPermutations = check(getPermutations(pC[3]))  
    firstSecond = checkBordersAndCombine(firstPermutations, secondPermutations)  
    thirdFourth = checkBordersAndCombine(thirdPermutations, fourthPermutations)  
    allCombinations__ = checkBordersAndCombine(firstSecond, thirdFourth)  
    allCombinations.extend(allCombinations__)  
  
print(allCombinations[0])
```
Running the program yields:
```
('P', 'B', 'V', 'C', 'W', '7', 'B', 'K', 'K', 'P', '0', 'Y', '8', '6', 'U', 'Y', '9', 'M', '8', 'O')
```
Formating it correctly and inputing it into the chal again gives us:
```
> rm /tmp/check*
> ./chal_patched 
Enter license key> 06788-9BBCK-KMOPP-UVWYY
[ERROR] Invalid license key!
> ls /tmp/ | grep check
check0HCUhx
checkALAL1v
checkN8Dg5E
checkWGTL4q
```
Thats the fourth binary! You already know whats the next step, we put it into ghidra :)
(Symbols renamed and comments added)
```c

undefined8 FUN_00100754(int param_1,long param_ 2) {

  /* [...] <- variable definitions removed for readability */
  
  if (param_1 < 2) {
    uVar1 = 1;
  }
  else {
    key = *(char **)(param_2 + 8);
    strLen = strlen(key);
    for (idx = 0; idx < (int)strLen; idx = idx + 1) {
      // DAT_001008e8 points to an integer value with len 20
      // All values are 0xFFFFFFFF except those at index 8, 7 and 5
      // 8 -> 8
      // 7 -> M
      // 5 -> Y
      // An Integer with value 0xFFFFFFFF is smaller than 0 so we fail the first check
      // for index 8,7 and 5 we don't
      // => our key is 8 at index 8, M at index 7 and Y at index 5
      if ((0 < *(int *)(&DAT_001008e8 + (long)idx * 4)) &&
         ((uint)(byte)key[idx] != *(uint *)(&DAT_001008e8 + (long)idx * 4))) {
        return 9;
      }
    }
    for (kdx = 0; kdx < (int)strLen; kdx = kdx + 1) {
      for (udx = 0; udx < 10; udx = udx + 1) {
        index = ((long)kdx * 10 + (long)udx) * 16;
        uStack_c = (uint)((ulong)*(undefined8 *)(&DAT_0 0100938 + index) >> 32);
        if (uStack_c == (byte)key[kdx]) {
          index1 = (int)*(undefined8 *)(&DAT_00100940 +  index);
          local_4 = (uint)((ulong)*(undefined8 *)(&DAT_00 100940 + index) >> 0x20);
          if ((byte)key[index1] != local_4) {
            return 1;
          }
        }
      }
    }
    uVar1 = 0;
  }
  return uVar1;
}
```
This leaves us with 2 possibilties, reverse the second for-loop or bruteforce the key. With the previous constrains we have about 500k (probably lots of duplicates included) possible keys left. At this point I was pretty hungry and wanted to take a break so I went for the second option and enjoyed some nice Gulasch at GPN:
```py
import subprocess  
import asyncio  
  
  
def background(f):  
    def wrapped(*args, **kwargs):  
        return asyncio.get_event_loop().run_in_executor(None, f, *args, **kwargs)  
  
    return wrapped  
  
  
@background  
def bruteforce(ix):  
    x = allCombinations[ix]  
    result = subprocess.Popen(  
        "qemu-aarch64 -L /usr/aarch64-linux-gnu <pathToBinary>/fourth " + getAsInput(x),  
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  
    result.communicate()[0]  
    return_code = result.returncode  
    if return_code == 0:  
        print("Success")  
        print(getAsInput(x))  
  
        exit(0)  
    if ix % 100 == 0:  
        print(ix)  
  
  
for ix in range(len(allCombinations)):  
    bruteforce(ix)
```
With that I'am able to test about 7k keys per minute
```
500k / 7k per min = 70 min worstcase
```
Actually the key was found around the 10 minute mark.
```
[...]
71800
71900
Success
UPPBKK0Y7C6B8VWY9M8O
```
Nice, lets bring it into the correct format:
```
./chal 
Enter license key> UPPBK-K0Y7C-6B8VW-Y9M8O
[CORRECT] License key validated

Decrypting product...

Welcome to GPN CTF 2024!

            ===========            
        ===================        
     -=======================-     
    ===========================    
  -===============-=============-  
  ===========::::::==============  
 =============:=========::::====== 
===============:::::::::::::=======
===========::=-:::::::::::::=======
==========::::=-::::::::::=========
=========::::::=-:-================
========::::::::=-:================
 ======::::::::::=-:============== 
  =====:::::::::::=-=============  
  -=====:::::::::::=============-  
    ===========================    
     -=======================-     
        ===================        
            ===========            


GPNCTF{W0nd3rful!_Y0u're_2_cl3ver_f0r_th4t_l1cens3_ch3ck!_W3ll_d0ne_<3}
```
