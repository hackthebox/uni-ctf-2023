<img src="../../assets/banner.png" style="zoom: 80%;" align=center />

<img src="../../assets/htb.png" style="zoom: 80%;" align='left' /><font size="6">BioBundle</font>

    16<sup>th</sup> 11 23 / Document No. D23.102.XX

    Prepared By: clubby789

    Challenge Author: clubby789>

    Difficulty: <font color=orange>Medium</font>

    Classification: Official





# Synopsis

Reversing a flag checker in an encrypted shared libary embedded in a binary.

## Skills Required
    - Basic decompiler use
    - Basic knowledge of dynamic loading
## Skills Learned
    - Use of `memfd_create`

# Solution

## Analysis

We'll begin by opening the binary in a decompiler.

```c
int32_t main(int32_t argc, char** argv, char** envp)
    void* _ = dlsym(get_handle(), "_")
    int32_t ret
    if (_ == 0) {
        ret = -1
    } else {
        char buf[0x80]
        fgets(buf: &buf, n: 0x7f, fp: stdin)
        buf[strcspn(&buf, "\n")] = 0
        if (_(&buf) == 0) {
            puts(str: "[x] Critical Failure")
        } else {
            puts(str: "[*] Untangled the bundle")
        }
        ret = 0
    }
    return ret
```

This calls `get_handle`, which likely returns a handle to a dynamically loaded libary. It then tries to resolve the symbol named `_` within it.
If this is successful, it reads input from the user and calls the loaded symbol on the user input.
If the return value is non-zero, we print a success message - otherwise, an error message.

### `get_handle`

```c
void* get_handle()
    int32_t fd = memfd_create(":^)", 0)
    if (fd == 0xffffffff) {
        exit(status: 0xffffffff)
    }
    for (int64_t i = 0; i u<= 0x3a77; i = i + 1) {
        char c = __[i] ^ 0x37
        write(fd, buf: &c, nbytes: 1)
    }
    char buf[0x1000]
    __builtin_memset(s: &buf, c: 0, n: 0x1000)
    sprintf(s: &buf, format: "/proc/self/fd/%d", fd)
    void* handle = dlopen(&buf, 1)
    if (handle == 0) {
        exit(status: 0xffffffff)
    }
    return handle
```

We begin by creating a file descriptor with `memfd_create`. `memfd_create` creates a temporary, in-memory anonymous file and returns a descriptor for it.
We then write each byte of some large buffer `__`, XOR'd with 0x37, into the new file.

We then get a path to access the anonymous file via /proc/self/fd, which contains the open file descriptors of the current process. Linux will allow us to treat these as symlinks to real files, even if they're created by `memfd_create`.

Finally, we call `dlopen` on the fd path. This reveals that the decrypted contents of `__` must be a shared library which is loaded into the process. We'll extract the library, using our decompiler to copy the data out. Using Binary Ninja, we can also decrypt it at this step as follows:

```py
with open('/tmp/lib.so', 'wb') as f:
    lib = bytes(b ^ 0x37 for b in bv.read(0x4080, 0x3a77))
    f.write(lib)
```

## Decompiling `lib.so`

`lib.so` contains a single user function named `_`. This function constructs a flag value on the stack, then compares it to the input parameter. With this, we can take the flag and solve the challenge.
