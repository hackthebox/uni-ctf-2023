![img](../../assets/banner.png)

<img src='../assets/htb.png' style='zoom: 80%;' align=left /> <font 
size='6'>Zombie Rolled</font>

4<sup>th</sup> December 2023 / Document No. D22.102.16

Prepared By: `aris`

Challenge Author(s): `maple3142`

Difficulty: <font color=red>Hard</font>

Classification: Official

# Synopsis

- In this challenge, we are provided with a custom public-key cryptosystem implementation with RSA encryption/decryption and a custom signature scheme that can sign/verify messages. The _magic_ equation ensures public key $a,b,c$ and private key $p,q,r$ satisfy $a/b+b/c+c/a=p/q+q/r+r/p$, so we can solve this diophantine equation to get the private key. After getting the private key, it is easy to unmix the mixed data to get the signature of the flag. The final step is to apply LLL to recover the flag from the signature.

## Description

- With the formula now in your team's possession, you face a significant challenge. The formula is constructed upon an exceedingly advanced equation that surpasses your current comprehension of mathematics. A note suggests a flaw, but the intricacies appear much too complex. It's crucial for the equation to be genuinely secure and not break in edge cases. Can you analyze this complex equation to bring an end to this tragic situation once and for all?

## Skills Required

- Good knowledge of the RSA cryptosystem
- Good knowledge of Elliptic Curves
- Basic understanding of algebraic curves and diophantine equations
- Basic knowledge of linear algebra
- Basic knowledge of lattice reduction techniques (i.e. LLL)

## Skills Learned

- Learn about solving diophantine equations with elliptic curves
- Get some experience with when and how to use LLL

# Enumeration

## Analyzing the source code

In this challenge, we are provided with two files:

- `chall.py`: The source code of the challenge, including the cryptosystem implementation and how the flag was _mixed_.
- `output.txt`: The output of `chall.py`, which is also a valid Python file that you can `exec` or copy-paste to your solve script.

The basic workflow of the `chall.py` is as follows:

1. Read the flag and ensure it is less than 64 bytes.
2. Generate a key pair $K$ and print the public key.
3. Encrypt/Decrypt and Sign/Verify the flag to ensure that the cryptosystem works correctly.
4. Mix the flag as follows:
   1. $s_1, s_2 = {Sign}_K(flag)$
   2. Output ${mix} = ({Encrypt}_K(s_1+s_2), {Encrypt}_K(s_1-s_2))$

In step 2, the key pair $K$ is generated as follows:

1. Generate 3 random primes $p,q,r$ to be the private key.
2. Calls a hidden function `derive_public_key` to derive the public key $a,b,c$ from $p,q,r$.
3. Compute $f=x/y={magic}(a,b,c)$ to be a part of the public key, where ${magic}(x,y,z)$ is defined as $x/y+y/z+z/x$
4. Let ${nb}$ be the byte length of $y$.
5. Check if ${magic}(p,q,r)=f$ holds. If not, go back to step 1.
6. Compute $d=x^{-1} \bmod{(p-1)(q-1)(r-1)}$

The `encrypt` function is defined as:

$$E(m) = m^x \pmod{y}$$

And the `decrypt` function is defined as:

$$D(c) = c^d \pmod{y}$$

With some simple calculations, we can see that $y=pqr$, so it is obvious that the `encrypt` and `decrypt` functions are just a (Multi-prime) RSA with $y=pqr$ being the modulus $n$ and $x$ being the public exponent $e$.

Now that we understand the `encrypt` and `decrypt` functions, let's take a look at the `sign` and `verify` functions. The `sign` function signs a message $m$ as follows:

1. Compute $h={\text{SHA}256}(m)$
2. Let $a, b$ be $m, h$ respectively.
3. Generate a random number $c$ within $[0, 2^{nb})$.
4. Compute $r={magic}(a,b,c) \pmod{n}$
5. Compute $s_1=D_K(r), s_2=D_K(c)$
6. Let $(s_1, s_2)$ be the signature of $m$ and return.

The corresponding `verify` function takes a message $m$ and a signature $(s_1, s_2)$ and verifies it as follows:

1. Compute $h={\text{SHA}256}(m)$
2. Let $a, b$ be $m, h$ respectively.
3. Compute $r=E_K(s_1)$
4. Compute $c=E_K(s_2)$
5. Check if $r={magic}(a,b,c) \pmod{n}$ holds. If so, return `True`, otherwise, return `False``.

It is easy to see `sign` and `verify` using RSA signing/verifying primitives $D_K$ and $E_K$ as a basic building block, then combine it with the ${magic}$ function and some randomness to build a nondeterministic signature scheme.

# Solution

## Finding the vulnerability

Obviously, it is necessary to factor $n=pqr$, but there is no easy way to do that when $p,q,r$ are all $1024$ bits long. But if you look at the code more closely, there is a mysterious function `derive_public_key` that is used to derive the public key $a,b,c$ from $p,q,r$, and its source code is not given. From this, it is reasonable to expect there is a way to compute the private key $p,q,r$ from the public key $a,b,c$.

## Private key recovery

The public key is three numbers $a, b, c$ and the private key is three primes $p, q, r$ satisfying:

$$\frac{a}{b} + \frac{b}{c} + \frac{c}{a} = \frac{p}{q} + \frac{q}{r} + \frac{r}{p}$$

Since $a, b, c$ are known, the problem can be reduced to solving an equation with $t$ being a known rational:

$$\frac{p}{q} + \frac{q}{r} + \frac{r}{p} = t$$

If you have seen [this](https://www.quora.com/How-do-you-find-the-positive-integer-solutions-to-frac-x-y+z-+-frac-y-z+x-+-frac-z-x+y-4?share=1) before, you may realize that it is possible to solve it by converting it into finding a rational point of an elliptic curve.

First, we rearrange the equation to:

$$C: pq^2 + p^2r + qr^2 = pqrt$$

In sage, we can check the genus of the curve $C$:

```python
Curve((p/q+q/r+r/p-t).numerator()).genus()
```

and it prints `1`, so it must be isomorphic to an elliptic curve.

To find it, Sage has a convenient [`EllipticCurve_from_cubic`](https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/constructor.html#sage.schemes.elliptic_curves.constructor.EllipticCurve_from_cubic) function to help us find that isomorphism:

```python
a, b, c = map(ZZ, pub)
t = a / b + b / c + c / a
P = QQ["a, b, c"]
a, b, c = P.gens()
eq = a / b + b / c + c / a - t
f = EllipticCurve_from_cubic(eq.numerator(), [1, 0, 0])
fi = f.inverse()
E = f.codomain()
print(E)
```

`E` is the elliptic curve we are looking for, and `f` and `fi` are the isomorphism and inverse isomorphism between the cubic curve $C$ and the elliptic curve $E$.

So once we have a rational point on $E$, say $G$. $f^{-1}(2G), f^{-1}(3G), \cdots$ will be solutions to the original equation. But finding $G$ using Sage's `.gen` method is pretty slow in this case.

Fortunately, the public key $a, b, c$ is already a solution to the equation, so we can let $G=f(a,b,c)$ to be a point on the curve $E$.

While it is also true that $f^{-1}(2G), f^{-1}(3G) \cdots$ are solutions to the equation, it is easy to see none of them is $p, q, r$ and they are getting bigger and bigger:

```python
G = f(pub)
p, q, r = fi(2 * G)
l = lcm(lcm(p.denom(), q.denom()), r.denom())
p, q, r = ZZ(p * l), ZZ(q * l), ZZ(r * l)
print(p.nbits())
```

Note that the challenge source also uses a secret `derive_public_key` function to get $a, b, c$ from $p, q, r$, so it is reasonable to expect our $G$ is already some multiple of another point $H$. Also, $a, b, c$ are roughly 3000 bits while $p, q, r$ are just 1024 bits, so that multiple probably isn't too big.

To perform point division, Sage has a `.division_point` to use, so we can get $p, q, r$ like this:

```python
G = f(pub)
p, q, r = fi(G.division_points(2)[0])
l = lcm(lcm(p.denom(), q.denom()), r.denom())
p, q, r = ZZ(p * l), ZZ(q * l), ZZ(r * l)
```

## Unmix the signature

Since the numerator and denominator of $t$ are used as a RSA public key $e, n$ in `encrypt` and `decrypt`, $n=pqr$. And now that we have $p, q, r$, it is easy to compute $d \equiv e^{-1} \pmod{\varphi(n)}$ to decrypt everything we want.

Note that ${mix} = ({Encrypt}_K(s_1+s_2), {Encrypt}_K(s_1-s_2))$, so we can decrypt the `mix` list using the recovered private key to get:

$$\begin{aligned}
m_1^d &\equiv s_1 + s_2 \pmod{n} \\
m_2^d &\equiv s_1 - s_2 \pmod{n}
\end{aligned}$$

Therefore the signature is given by $s_1 = 2^{-1} (m_1^d+m_2^d)$, $s_2 = 2^{-1} (m_1^d-m_2^d)$.

## Recovering the flag from signature

This challenge used a custom signature scheme:

$$\begin{aligned}
s_1 &\equiv (\frac{a}{b} + \frac{b}{c} + \frac{c}{a})^d \pmod{n} \\
s_2 &\equiv c^d \pmod{n}
\end{aligned}$$

with $a$ being the message and $b={\text{SHA}256}(a)$.

First, we can encrypt those two signature values to get $r=s_1^c$ and $c=s_2^e$, so it would be:

$$ab^2 + a^2c + bc^2 \equiv rabc \pmod{n}$$

So we have only one equation but with two unknowns $a,b$, and there is no easy way to express the relationship of $a={\text{SHA}256}(b)$, so we couldn't solve this easily.

The trick here is to see that $a$ is the flag, so $a<2^{512}$. $b$ being a SHA256 hash so we have $b<2^{256}$, and $c$ being generated by `randbelow(1 << self.nb)` means $c<2^{384}$. So $x=ab^2+a^2c+bc^2$ and $y=abc$ will be much smaller than $n \approx 2^{3 \times 1024}$.

So we can rewrite the equation and remove the modulo using the definition:

$$x = ry - zn$$

Note that $x, y$ are much smaller than $r$ and $n$, so we can apply LLL to find them.

For example, we have the following basis:

$$B=\begin{bmatrix}
r & 1 \\
n & 0
\end{bmatrix}$$

It is easy to see $(y,-z) \cdot B = (x, y)$, so the short vector $(x, y)$ is spanned by the basis $B$, therefore we can expect it to be found by LLL.

One caveat here is that the resulting short vector may not necessarily be the $(x,y)$ we want, because when $g = \gcd(x,y) \neq 1$, then $(x/g, y/g)$ will be an even shorter vector in the basis. So will need to brute force $g$ to find the correct $(x,y)$.

Now that we have $x,y$, and $c$ is also known, use Groebner basis to solve the following system:

$$\begin{aligned}
x &= ab^2+a^2c+bc^2 \\
y &= abc
\end{aligned}$$

And the solution $a$ will be the flag.

## Exploitation

### Import essential packages and loading data

We start by importing the essential packages and loading the data by `exec`-ing the output file:

```python
from sage.all import *
from Crypto.Util.number import long_to_bytes
from chall import PublicKey

with open("output.txt") as f:
    exec(f.read())
```

### Derive the private key

All we need is to put how we did in the previous into a function:

```python
def derive_private_key(pub):
    a, b, c = map(ZZ, pub)
    rhs = a / b + b / c + c / a
    P = QQ["a, b, c"]
    a, b, c = P.gens()
    eq = a / b + b / c + c / a - rhs
    f = EllipticCurve_from_cubic(eq.numerator(), [1, 0, 0])
    fi = f.inverse()
    G = f(pub)
    aa, bb, cc = fi(G.division_points(2)[0])
    l = lcm(lcm(aa.denom(), bb.denom()), cc.denom())
    aa, bb, cc = ZZ(aa * l), ZZ(bb * l), ZZ(cc * l)
    assert aa / bb + bb / cc + cc / aa == rhs
    return int(aa), int(bb), int(cc)
```

It first computes the $t$ in `rhs`, then use `EllipticCurve_from_cubic` to find an Elliptic Curve and an isomorphism. Map the public key to a curve point and use `.division_points` to divide it by 2 and map it back to get the $p, q, r$.

### Unmix the signature

Since we have the private key, decrypting the mixed signatures and solving a simple linear system is enough:

```python
def unmix(d, n, mix):
    s1ps2 = pow(mix[0], d, n)  # s1 + s2
    s1ms2 = pow(mix[1], d, n)  # s1 - s2
    i2 = pow(2, -1, n)
    s1 = (s1ps2 + s1ms2) * i2 % n
    s2 = (s1ps2 - s1ms2) * i2 % n
    return s1, s2
```

### Recover the flag from signature

We first implement the LLL method to find a small solution $x,y$ to $x/y \equiv r \pmod{n}$ equation:

```python
def solve_xy(r, n):
    # find small x, y such that x/y=r (mod n)
    B = matrix(ZZ, [[r, 1], [n, 0]])
    B = B.LLL()
    x, y = map(abs, B[0])
    assert x * pow(y, -1, n) % n == r
    return x, y
```

Then write a function to use it and do the $g$ brute force, and solve the system using Groebner basis:

```python
def recover_flag(n, e, s1, s2):
    r = pow(s1, e, n)
    c = pow(s2, e, n)

    x, y = solve_xy(r, n)

    P = QQ["a, b"]
    a, b = P.gens()
    for g in range(1, 100):
        # we don't know what g is, but expect it to be small
        xx, yy = x * g, y * g
        I = P.ideal(
            [
                a * b**2 + a**2 * c + b * c**2 - xx,
                a * b * c - yy,
            ]
        )
        try:
            sol = I.variety()[0]
            return int(sol[a])
        except IndexError:
            pass
```

### Getting the flag

A final summary of all that was said above:

1. Recover the private key by solving a diophantine equation with Elliptic Curve
2. Unmix the signature using the private key
3. Solve the equation $x/y \equiv r \pmod{n}$ using LLL
4. Bruteforce $g$ and solve the system using Groebner basis to get the flag

Putting everything together:

```python
f = PublicKey.magic(pub)
e = f.numerator
n = f.denominator

p, q, r = derive_private_key(pub)
assert p * q * r == n
print(p, q, r)
phi = (p - 1) * (q - 1) * (r - 1)
d = pow(e, -1, phi)
s1, s2 = unmix(d, n, mix)
flag = recover_flag(n, e, s1, s2)
print(long_to_bytes(flag))
```