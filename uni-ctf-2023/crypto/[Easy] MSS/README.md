![img](../assets/banner.png)

<img src='../assets/htb.png' style='zoom: 80%;' align=left /> <font 
size='6'>MSS</font>

28^{th} 2023 / Document No. D22.102.16

Prepared By: `aris`

Challenge Author(s): `aris`

Difficulty: <font color=green>Easy</font>

Classification: Official

# Synopsis

- This challenge teaches players about the Mignotte Secret Sharing scheme. In this scheme, we are able to obtain the secret modulo $n$ distinct relatively prime moduli and combine these partial solutions with CRT to get the entire secret $a_0$.

## Description

- The military possesses a server containing crucial data about the virus and potential cures, secured with encryption and a key distributed using a secret sharing scheme. However, authorized members holding parts of the key are infected, preventing access to the research. Fueled by your cryptography passion, you and your friends aim to hack into the server and recover the key. Can you succeed in this challenging mission?

## Skills Required

- Basic knowledge of Secret Sharing schemes.
- Familiar with polynomials.
- Know how to combine partial solutions to obtain a full solution.

## Skills Learned

- Learn how to apply CRT to combine multiple partial solutions.
- Learn about the Mignotte Secret Sharing.

# Enumeration

## Analyzing the source code

In this challenge, we are provided with one file `server.py` which is the main script that runs when we connect to the remote instance.

From the welcome message, we understand that the challenge is about secret sharing schemes. Such a scheme usually requires two parameters having been set:

- The finite field $GF(p)$ in which all the operations will be performed.
- The degree of the polynomial to be interpolated, say `d`.
- The number of users in the scheme `n` (or equivalently, the number of shares required to interpolate the polynomial).

### Polynomials in Secret Sharing schemes

Before moving on, it is important to recall how secret sharing schemes work. The purpose of such a scheme is key distribution among a group of users where each user contributes to this distrubution by submitting their ***share***; as it is called. First, a $d$-degree polynomial needs to be defined under a finite field $GF(p)$.
$$P(x) = a_0 + a_1x + a_2x^2 + \dots + a_dx^d \pmod p$$
Moreover let $n$ be the number of users that intend to distribute the secret. It turns out that $P$ can be uniquely determined (i.e. interpolated) only if $n > d$. In other words, there are needed at least as many shares as the number of coefficients of $P$.

Back to our problem, there are two things that stand out.

- The polynomial being used is not defined in a finite field $GF(p)$. This is trivial to see from the `poly` function which substitutes the polynomial with the value of $x$ and the result is not reduced modulo any prime number $p$.

```python
def poly(self, x):
    return sum([self.coeffs[i] * x**i for i in range(self.d+1)])
```

- The degree of the polynomial is $30$ but the maximum number of shares is only $19$ which initially might make us think that it is not possible to interpolate the polynomial. This is trivial to see from the constructor of the MSS class.

```python
class MSS:
    def __init__(self, BITS, d, n):
    self.d = d
    self.n = n
    self.BITS = BITS
    ...
    
def main():
    mss = MSS(256, 30, 19)
    ...
```

Our final task is to recover the $a_0$ coefficient of the polynomial which is the key that is eventually used to encrypt the flag.

```python
self.key = bytes_to_long(os.urandom(BITS//8))
self.coeffs = [self.key] + [bytes_to_long(os.urandom(self.BITS//8)) for _ in range(self.d)]
```

```python
def encrypt_flag(self, m):
    key = sha256(str(self.key).encode()).digest()
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(m, 16))
    return {'iv': iv.hex(), 'enc_flag': ct.hex()}
```

Therefore we can deduce the following about the secret sharing scheme.

- The polynomial is defined over the integers and is of degree $d = 30$.
- The maximum number of users in this scheme is $n = 19$.
- The size of each coefficient is 256 bits.
- All coefficients but $a_0$ are random 256-bit integers. $a_0$ itself is the key that we have to recover.

Now let us examine the flow of the application and how we can interact with it.

1. We can send our ID to the server and receive our share back.
2. We can receive the encrypted flag from the server.

Since the key is unknown and AES is considered secure, we will experiment with the first option. The first option has the following restrictions.

```python
def get_share(self, x):
    if x > 2**15:
        return {'approved': 'False', 'reason': 'This scheme is intended for less users.'}
    elif self.n < 1:
        return {'approved': 'False', 'reason': 'Enough shares for today.'}
    else:
        self.n -= 1
        return {'approved': 'True', 'x': x, 'y': self.poly(x)}
```

1. Our ID must not be greater than 15 bits.
2. Each time we send an ID, the number of shares is decreased by $1$ so we are allowed to send only 19 requests.
3. If we attempt to send more, our request is not accepted.

# Solution

## Finding the vulnerability

This challenge demonstrates why it is important to use secure parameters for secret sharing schemes and to define polynomials in finite fields. Firstly, the problem with recovering the coefficients directly is that there are 31 unknowns but we are able to obtain only 19 relations with these variables. Let us redefine the polynomial $P$:
$$P(x) = a_0 + a_1x + a_2x^2 + \dots + a_{30}x^{30}$$
Assuming the player is familiar with modular arithmetic, they can quickly observe that:
$$P(x_i) \pmod {x_i} \equiv a_0 \pmod {x_i}$$
Therefore, by reducing the $i$-th share modulo $x_i$ we get the first coefficient $a_0$ (i.e. our secret) reduced modulo $x_i$. That is because all the other terms are eliminated as they are multiples of $x_i$.
$$P(x_i) = a_0 + a_1x_i + a_2x_i^2 + \dots + a_{30}x_i^{30}$$
A question might arise regarding how useful this is. There is a well known theorem known as the Chinese Remainder Theorem (CRT) that helps us to find a full solution given enough partial solutions. More specifically, given the following relations:
$$x \equiv c_1 \pmod {n_1}\\
x \equiv c_2 \pmod {n_2}\\
\vdots\\
x \equiv c_k \pmod {n_k}$$
and assuming that $n_i$ are all relatively prime, the Chinese Remainder Theorem can find a solution for $x$ modulo $N = n_1n_2 \dots n_k$.

Note that this challenge can become significantly easier if the player is already aware of the well known secret sharing scheme known as Mignotte Secret Sharing scheme (MSS).

Since we are limited to send at most 15-bit IDs, we would need at least $\lceil{\dfrac{256}{15}}\rceil = 18$ shares in order to recover the entire 256-bit secret which we are able to do since the upper limit is 19. More specifically, with 18 requests we can recover 15*18 = 270 bits of the key.



## Exploitation

Let us adjust the Chinese Remainder Theorem to our challenge data. The idea is to send 18 distinct $x_i$ as IDs and reduce the share modulo $x_i$. Then we obtain $a_0 \pmod {x_i}$. Repeating this we obtain several equations for the key $K$:
$$K \equiv a_0 \pmod {x_0}\\
K \equiv a_0 \pmod {x_1}\\
\vdots\\
K \equiv a_0 \pmod {x_{17}}$$
This is exactly in the form of the Chinese Remainder Theorem so we can apply it to recover the full key $K$. To avoid the $x_i$ having common factors, we can define them to be prime numbers.

Let us write a function that randomly selects 18 15-bit primes, sends them to the server as the user ID and receives the corresponding share.

```python
from Crypto.Util.number import getPrime

def obtain_shares():
    X = [getPrime(15) for _ in range(n)]
    RK = [] # reduced keys

    for x in X:
        payload = json.dumps({'command': 'get_share', 'x': x})
        io.sendlineafter(b'query = ', payload.encode())
        share = json.loads(io.recvline().strip())['y']
        RK.append(share % x)
		
    return X, RK

d = 30
n = 19
```

Having obtained the shares, we can use Sympy's implementation of the CRT and solve for the key.

```python
from sympy.ntheory.modular import crt

def solve_crt(X, rk):
    return int(crt(X, rk)[0])
```

Finally, we can hash the key as seen in the challenge source, request the encrypted flag and decrypt it.

```python
from hashlib import sha256

def calculate_decryption_key(key):
    return sha256(str(key).encode()).digest()

def request_encrypted_flag():
    payload = json.dumps({'command': 'encrypt_flag'})
    io.sendlineafter(b'query = ', payload.encode())
    io.recvuntil(b'flag : ')
    
    data = json.loads(io.recvuntil(b'}').strip())
    iv = bytes.fromhex(data['iv'])
    encflag = bytes.fromhex(data['enc_flag'])
    return iv, encflag


from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES

def decrypt_flag(key, iv, enc_flag):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encflag), 16).decode()
```

### Getting the flag

A final summary of all that was said above:

1. Notice that the degree of the polynomial $d = 30$ is greater than the number of shares we are allowed to obtain $n = 19$.
2. Write down how $x_i$ are substituted in the polynomial $P$ and take advantage of the modular arithmetic properties to get the key $a_0$ reduced modulo different relatively prime moduli.
3. Having obtained enough modular congruences, apply the CRT to find the whole key.
4. Recalculate the decryption key
5. Request the encrypted flag and decrypt it.

These steps can be represented by code with the `pwn()` function:

```python
def pwn():
    X, RK = obtain_shares()
    key = solve_crt(X, RK)
    aes_key = calculate_decryption_key(key)
    iv, enc_flag = request_encrypted_flag()
    flag = decrypt_flag(key, iv, enc_flag)
    print(flag)
    
pwn()
```
