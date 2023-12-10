![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font 
size='6'>Mayday Mayday</font>

28<sup>th</sup> 2022 / Document No. D22.102.16

Prepared By: `aris`

Challenge Author(s): `aris`

Difficulty: <font color=green>Medium</font>

Classification: Official

# Synopsis

- In this challenge, the players have to figure out how to factor $N$ either by exploiting the partial leakage of the CRT components. Even though there is a [paper](https://eprint.iacr.org/2022/271.pdf) that describes the exploitation steps, it is feasible for a player to figure them out themselves, as well.

## Description

- After successfully obtaining the research papers by extracting the encryption key, a new obstacle arises. The essential information regarding potential cures, including formulas and test results, is shielded by another layer of encryption. Can you overcome this additional challenge to reveal the final formula, enabling you to initiate the cure creation process?

## Skills Required

- Basic Python source code analysis.
- Familiar with translating mathematical parameters into relations and equations.
- Knowledge of the RSA-CRT variant.

## Skills Learned

- Learn how to factor the RSA modulus $N$ from partial leakage of $d_p$ and/or $d_q$.
- Learn how to research on the internet for papers and/or cryptographic vulnerabilities.

# Enumeration

## Analyzing the source code

Looking at `source.py`, we can see that the flow of the script is pretty straight forward. There is a class with an RSA implementation and the flag is encrypted with RSA. What stands out is the key generation process.

```python
class Crypto:
    def __init__(self, bits):
        self.bits = bits
        self.alpha = 1/9
        self.delta = 1/4
        self.known = int(bits*delta)
    
    def keygen(self):
        while True:
            p, q = [getPrime(self.bits//2) for _ in '__']
            self.e = getPrime(int(self.bits*alpha))
            φ = (p-1)*(q-1)
            try:
                dp = pow(e, -1, p-1)
                dq = pow(e, -1, q-1)
                self.n = p*q
                break
            except:
                pass
        
        return (self.n, self.e), (dp, dq)

    def encrypt(self, m):
        return pow(m, self.e, self.n)
```

The main script body is also straight forward.

```python
rsa = Crypto(2048)
_, (dp, dq) = rsa.keygen()

m = bytes_to_long(FLAG)
c = rsa.encrypt(m)

with open('output.txt', 'w') as f:
    f.write(f'N = 0x{rsa.n:x}\n')
    f.write(f'e = 0x{rsa.e:x}\n')
    f.write(f'c = 0x{c:x}\n')
    f.write(f'dp = 0x{(dp >> (rsa.bits//2 - rsa.known)):x}\n')
    f.write(f'dq = 0x{(dq >> (rsa.bits//2 - rsa.known)):x}\n')
```

The basic workflow of the script is as follows:

1. An RSA-2048 cryptosystem is initialized.
2. Then there is the key generation process which returns $d_p, d_q$ as the private keys instead of just $d$. This is known as the RSA-CRT variant of RSA and is considered faster than the standard decryption method that uses $d$.
3. The flag is encrypted.
4. We are given $N, e, c$ as well as a few MSB of the private keys $d_p, d_q$.

What is worth to analyze is the choice of the public exponent $e$ and the leakage of the secret CRT exponents $d_p, d_q$.

## Analyzing the RSA-CRT components

Apart from the standard parameters, there are also three values that we have not discussed yet. Namely, `alpha`, `delta` and `known`. We will denote `alpha` as $α$ and `delta` as $δ$.

The public exponent is a random prime number and its size is bounded by $\lfloor 2048 \cdot \dfrac{1}{9} \rfloor = 227$ bits. Also, the size of the leakage is $\dfrac{2048}{2} - 2048*δ = 1024 - \lfloor 2048 \cdot \dfrac{1}{4} \rfloor = 512$ bits which is $\dfrac{1}{4}$ the size of $N$. The choice of the public exponent's size does not really look that random so this makes us think that the bounds for the RSA-CRT components are chosen in a way that makes the cryptosystem vulnerable.

Before moving on, let us write a function that loads the data from the output file.

```python
def load_data():
    with open('output.txt') as f:
        exec(f.readline())
        exec(f.readline())
        exec(f.readline())
        dp_msb = eval(f.readline().split(' = ')[1].strip())
        dq_msb = eval(f.readline().split(' = ')[1].strip())
        return N, e, c, dp_msb, dq_msb
```

# Solution

## Finding the vulnerability

Usually, when there is some kind of leakage of secret parameters, our first thought is applying Coppersmith's method for univariate or bivariate polynomials to find small roots. However this method does not work for arbitrary leakage sizes. We cannot apply this method directly in this challenge, first we should perform an additional step.

At this point, it is important to note that this challenge can be solved either manually, either by finding the right [paper](https://eprint.iacr.org/2022/271.pdf). One can find this paper by searching around the keywords "rsa factoring crt exponents public exponent". In the case which the MSB of $d_p, d_q$, which is our case, is significantly easier than the LSB case. The LSB case was demonstrated in Bauhinia CTF 2023 with the challenge `grhkm's babyRSA`.

The core vulnerability of this RSA setup is the bound of $e$ and the size of the leakage of the RSA-CRT exponents which allow us to recover the entire secret exponents and factor $N$ as a result. The exploitation will be done in two steps.

1. In the first step, we have to recover the two numbers $k,l$ such that $ed_p = 1 + k(p-1)$ and $ed_q = 1 + l(q-1)$.
2. In the second step, we compute the unknown LSB of $d_p, d_q$ and then we obtain $p,q$ with a single substitution.

We will follow the section (3.1) of the paper. We can see that it begins with calculating the product $k \cdot l$. Let:
$$d_p = A*2^i + B\\
d_q = C*2^i + D$$
where $A$ the known MSB and $B$ the unknown LSB and $i$ the number of the unknown bits. Then we can compute $A = k \cdot l$ as:
$$A = \lceil \dfrac{2^{2i}e^2 A C}{N} \rceil$$
Let us write a function that computes the product $k \cdot l$.

```python
def calculate_product_kl(dp_msb, dq_msb, N, e, i):
    return ceil(((2**(2*i) * e**2 * dp_msb * dq_msb) / N))

bits = 2048
known = 512
N = ...	# see output.txt
e = ...
dp_msb = ...
dq_msb = ...
i = bits//2 - known

A = calculate_product_kl(dp_msb, dq_msb, N, e, i)
```

According to the paper, we can write:
$$k + l = 1 - kl(N-1) \pmod e\quad\quad\quad\quad(1)$$
We know that $0 \leq k + l < 2e$ so either $0 \leq k+l < e$ or $e \leq k + l < 2e$. In the first case, the modulo is not applied at all while in the second case we expect that the sum $k+l$ is reduced by a single multiple of $e$ so by adding $e$ we get the unreduced sum. This is because $2e$ and $e$ differ by one multiple of $e$.

For this part, the method of the paper calculates $k,l$ as the roots of two polynomials defined over $GF(e)$. It turns out that this is not required at all. There are two unknowns $k,l$ so we would need two relations in terms of $k,l$ to solve a system of equations. The first relation is already known $A = k \cdot l$. For the second equation we can use $(1)$. Therefore we know the following:
$$k \cdot l = A\\
k + l = 1 - A(N-1)$$
Knowing these, we can solve for $k,l$ over the integers directly. Let us use SageMath to solve this system of equations. In the case it returns nothing, it is probably because the sum is larger than $e$ so we would have to add $e$ once.

```python
def recover_k_and_l(A, N, e):
    k_plus_l = (1-A*(N-1)) % e

    k, l = var('k,l', domain=ZZ)
		
    # check both possibilities
    for s in [k_plus_l, k_plus_l + e]:
        try:
            sol = solve([k*l == A, k+l == s], k, l, solution_dict=True)[0]
            k, l = int(sol[k]), int(sol[l])
            break
        except:
            pass

    assert A == k*l

    return k, l
```

## Solving for the private CRT exponents

Having recovered $k,l$, we can proceed with recovering $d_p, d_q$. We know that:
$$ed_p \equiv 1 \pmod {p-1}$$
Recovering $p$ is enough to factor $N$ so we from now on we care only about the recovery of $d_p$ and not $d_q$. Doing some elementary algebra we can rewrite these relations as following:
$$ed_p + k - 1 \equiv 0 \pmod{p}$$
and substituting $d_p, d_q$ using the known and unknown bits:
$$\begin{align}e(A*2^i+B) + k - 1 &\equiv 0 \pmod p\\
2^iAe + Be + k - 1 \equiv 0 \pmod p
\end{align}$$
According to the paper, we can define the polynomial $P$ as below.
$$P(x) = x + e^{-1}(A2^i + k - 1)$$
over $\mathbb{Z}/_{kN}\mathbb{Z}$. The root of this polynomial is $x = B$ so all we have to do is apply the Coppersmith's method on $P$ to find the small roots. Note that the bit length of $kN$ is approximately $\approx 1024 + 2048 = 3072$ bits and $B$ is approximately $\approx 1024$ bits which is less than $\dfrac{1}{3}$ of $kN$. This means that Coppersmith is guaranteed to return as a solution.

Once we recover $d_p$, we can compute $p$ as:
$$p = \dfrac{ed_p + k - 1}{k}$$
and factor $N$.

```python
def factor(dp_msb, N, e, k, l, i):
    # we found k,l but probably in the wrong order
    # try both
    for kt, _ in [[k, l], [l, k]]:
        try:
            x = PolynomialRing(Zmod(kt*N), 'x').gens()[0]
            F = x + (e*dp_msb*2**i + kt - 1) * pow(e, -1, kt*N)
            dp_lsb = int(F.small_roots(X=2**i, beta=0.5)[0])
            dp = (dp_msb << i) + dp_lsb
            
            p = (e*dp+kt-1) // kt
            q = N // p
            
            assert N == p * q
    
            return p, q
        except:
            pass
```

## Exploitation

Once we have factored $N$, we can decrypt the flag.

```python
def decrypt(N, e, p, q, c):
    phi = (p-1)*(q-1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    return m
```

### Getting the flag

A final summary of all that was said above:

1. Notice that the bound of the public exponent $e$ and the size of the leakage of $d_p, d_q$ enable us to recover the private CRT exponents.
2. By minimal researching on the internet we can find the paper that describes the exploitation process. Alternatively, we can proceed with solving it by figuring out the equations ourselves.
3. Having factored $N$, we can decrypt the flag.

This recap can be represented by code with the `pwn()` function:

```python
from Crypto.Util.number import long_to_bytes as l2b

def pwn():
    N, e, c, dp_msb, dq_msb = load_data()
    bits = 2048
    known = 512
    i = bits//2 - known
    A = calculate_product_kl(dp_msb, dq_msb, N, e, i)
    k, l = recover_k_and_l(A, N, e)
    p, q = factor(dp_msb, N, e, k, l, i)
    flag = decrypt(N, e, p, q, c)
    print(l2b(flag))
 
pwn()
```
