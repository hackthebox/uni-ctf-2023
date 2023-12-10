<img src="../../assets/banner.png" style="zoom: 80%;" align=center />

<img src="../../assets/htb.png" style="zoom: 80%;" align='left' /><font size="6">RiseFromTheDead</font>

    22<sup>nd</sup> 11 23 / Document No. D23.102.XX

    Prepared By: clubby789

    Challenge Author: clubby789

    Difficulty: <font color=red>Hard</font>

    Classification: Official

# Synopsis

RiseFromTheDead is a Hard reversing challenge. Players will reverse engineer a binary in order to understand an encoding scheme, then use a core dump to recover the original flag.

## Skills Required
    - Decompiler usage
    - Basic data structure knowledge
## Skills Learned
    - Core file analysis
    - Pwntools automation

# Solution

We're given a binary and a core dump for it.

## Analysis

We'll begin by opening the provided binary in a decompiler.

```c
int32_t main(int32_t argc, char** argv, char** envp)

int32_t ret
if (argc s<= 1) {
    char const* const rdx_1 = "./program"
    if (argc == 1) {
        rdx_1 = *argv
    }
    fprintf(stream: stderr, format: "Usage: %s <secret file>\n", rdx_1)
    ret = -1
} else {
    int32_t fd = open(file: argv[1], oflag: 0)
    ret = fd
    if (fd == 0xffffffff) {
        perror(s: "Opening file")
    } else {
        // PROT_READ|PROT_WRITE, MAP_PRIVATE
        char* flag = mmap(addr: nullptr, len: 0x1000, prot: 3, flags: 2, fd, offset: 0)
        if (flag == 0) {
            perror(s: "Mapping file")
            ret = -1
        } else {
            char* newline = strchr(flag, '\n')
            if (*newline != 0) {
                *newline = ' '
            }
            memset(flag + 256, 0, 0x1000 - 256);
            void** rax_3 = init_shuffle_list(flag)
            memset(flag, 0, 256);
            shuf(rax_3, flag)
            puts(str: flag)
            kill(0, 0xb)
            ret = 0
        }
    }
}
return ret
```

This opens up some file (presumably the flag) and mmaps it into memory as a writable buffer, removing any trailing newline and anything beyond 256 characters.

We then call `init_shuffle_list` using the flag, before clearing the whole flag buffer and calling `shuf` on it with the result of `init_shuffle_list`. Finally, we print the new value of `flag` before issuing a SIGSEGV to dump the core.

### `init_shuffle_list`

```c
struct SomeStruct* init_shuffle_list(char* flag)

int32_t fd = open(file: "/dev/urandom", oflag: 0)
struct SomeStruct* ss = nullptr
char* i = flag
do {
    uint8_t num
    read(fd, buf: &num, nbytes: 1)
    while (true) {
        num = zx.q(num)
        if (pos_in_list(ss, (num.d).b) == 0) {
            break
        }
        read(fd, buf: &num, nbytes: 1)
    }
    append_list(&ss, (num.d).b, *i)
    i = &i[1]
} while (i != &flag[0x100])
close(fd)
return ss
```

We iterate over each character of the flag. We repeatedly get a random byte from `/dev/urandom` and check if it's in a list already. If it is not, we add the number and current flag character to the list.

### `pos_in_list` and `append_list`

```c
bool pos_in_list(struct SomeStruct* arg1, uint8_t pos)

if (arg1 == 0) {
    return 0
}
do {
    if (arg1->pos == pos) {
        return 1
    }
    arg1 = arg1->next
} while (arg1 != 0)
return 0
```

From this we can see that `SomeStruct` is a linked list structure. We iterate forward until finding a null `next`. If any entries in the list have a matching `pos` value we return true.

```c
struct SomeStruct* append_list(struct SomeStruct** head, uint8_t pos, char chr)
struct SomeStruct* cur = *head
struct SomeStruct* new_head
if (cur == 0) {
    new_head = malloc(bytes: 0x10)
    new_head->next = 0
    new_head->pos = pos
    new_head->chr = chr
    *head = new_head
} else {
    struct SomeStruct* new_cur
    do {
        new_cur = cur
        cur = cur->next
    } while (cur != 0)
    struct SomeStruct* next = malloc(bytes: 0x10)
    new_cur->next = next
    next->next = 0
    new_cur->next->pos = pos
    new_head = new_cur->next
    new_head->chr = chr
}
return new_head
```

We can add a `chr` field to the end of our structure which contains the character given. This is a simple linked list append, initialising the head of the list if it is currently `NULL`.

### `shuf`

```c
void shuf(struct SomeStruct* arg1, char* buffer)

if (arg1 != 0) {
    do {
        buffer[zx.q(arg1->pos)] = arg1->chr
        arg1->chr = 0
        arg1 = arg1->next
    } while (arg1 != 0)
}
```

For each entry in the linked list, we set `buffer[pos]` to `chr`, before setting the `chr` field to 0 and going to the next entry.

This program effectively generates a list of 256 unique positions associated with a character, then places them into a buffer in the newly generated order.

## Recovering the flag

The linked list still exists at the time the program crashes, meaning that we are able to parse the core file and retrieve the order of the list. However, the binary is optimised and the pointer to the list does not exist on the stack. We'll have to scan through memory to locate it.

We'll use `pwntools` `corefile` module to examine the file. First, we need to open it and scan through memory mappings to find the heap, the first mapping in memory that isn't associated with a file.

```py
from pwn import *

core = Corefile("./core")
for mem in core.mappings:
    if mem.name == '':
        heap = mem
        break
else:
    print("heap not found")
    exit()
```

Using our knowledge of the flag format, the linked list is built in such a way that the first element will correspond to the position of `H`, the second to `T`, the third to `B` and so on. To locate the first entry in the list, we first need to find the position of 'H':

```py
for mem in core.mappings:
    if 'flag' in mem.name:
        flag = mem
        break
else:
    print("flag not found")
    exit()


shuffled_flag = core.read(flag.start, 255)
h_pos = shuffled_flag.index(b'H')
print(f"`H` is at {h_pos}")
```

We're now looking for a structure in heap memory of this format:

- 8 byte pointer, should be within the heap
- The position of h as ab yte
- A null byte

Malloc will round up the size of our list struct to 16, so we'll search in chunks of 16.

```py
for addr in range(heap.start, heap.stop, 16):
    ptr, pos, char = struct.unpack("PBB", core.read(addr, 10))
    if ptr in heap and pos == h_pos and char == 0:
        list_head = addr
        break
else:
    print("list not found")
    exit()
```

We can now simply traverse the linked list, following the pointers and taking the provided character from the shuffled buffer.

```py
flag = ""
while addr:
    addr, pos = struct.unpack("PB", core.read(addr, 9))
    flag += chr(shuffled_flag[pos])
print(f"Flag is: `{flag.strip()}`")
```
