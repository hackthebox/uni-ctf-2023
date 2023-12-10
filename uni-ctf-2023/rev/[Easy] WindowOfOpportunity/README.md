<img src="../../assets/banner.png" style="zoom: 80%;" align=center />

<img src="../../assets/htb.png" style="zoom: 80%;" align='left' /><font size="6">WindowOfOpportunity</font>

  5<sup>th</sup> 12 23 / Document No. D23.102.XX

  Prepared By: clubby789

  Challenge Author: clubby789

  Difficulty: <font color=green>Easy</font>

  Classification: Official






# Synopsis

WindowOfOpportunity is an Easy reversing challenge. Players will reverse a flag checking algorithm and write a brute-force or Z3 solver.

## Skills Required
    - Decompiler usage
## Skills Learned
    - Z3py usage

# Solution

If we run the binary, we're prompted for a password. Entering a random string gives us an error and the binary exits.

## Analysis

```c
int32_t main()
    puts(str: "A voice comes from the window... 'Password?'")
    char buf[0x2a]
    fgets(buf: &buf, n: 0x2a, fp: stdin)
    int32_t i = 0
    int32_t ret
    while (true) {
        if (i u> 0x24) {
            puts(str: "The window opens to allow you passage...")
            ret = 0
            break
        }
        if (buf[sx.q(i + 1)] + buf[sx.q(i)] != arr[sx.q(i)]) {
            puts(str: "The window slams shut...")
            ret = -1
            break
        }
        i = i + 1
    }
    return ret
```

After receiving the password, we loop from 0 to 0x24. For each value, we add together the `i`th and `i+1`th characters of the input, comparing it to a constant byte array value in `arr`.

The binary is creating a sliding window of size 2 over the input, and summing the values to compare against a constant. To solve this, we can either bruteforce byte-by-byte, or use a symbolic solution with Z3 py.

First we'll need to extract the bytes from the `arr` array into our script:

```py
sums = [ ... ]
```

We'll then prepare our Z3 solver and input
```py
from z3 import *
s = Solver()
# Create symbolic input 8-bit values to represent the password 
inp = [BitVec(f"flag_{i}", 8) for i in range(len(sums) + 1)]
```

We now need to add some constraints - we know from the flag format the password will begin `HTB{`.
```py
for i, c in enumerate(b"HTB{"):
    s.add(inp[i] == c)
```

We now just need to implement the sliding window, and constrain our solver using it.
```py
for i in range(len(sums)):
    s.add(inp[i] + inp[i+1] == sums[i])
```

We're now ready to evaluate our model, convert each symbolic value to a byte and print out the flag.

```py
print(s.check())
m = s.model()
bs = [m.eval(i).as_long() for i in inp]
print(bytes(bs))
```