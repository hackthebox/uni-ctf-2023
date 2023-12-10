from sage.all import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
from fractions import Fraction
from hashlib import sha256

with open("output.txt") as f:
    exec(f.read())


def fraction_mod(f, n):
    return f.numerator * pow(f.denominator, -1, n) % n


class PublicKey:

    def __init__(self, pub):
        self.pub = pub
        self.f = self.magic(pub)
        self.nb = (self.f.denominator.bit_length() + 7) // 8

    def encrypt(self, m):
        return pow(m, self.f.numerator, self.f.denominator)

    def verify(self, m, sig):
        s1, s2 = sig
        h = bytes_to_long(sha256(m.to_bytes(self.nb, "big")).digest())
        a, b = m, h
        r = self.encrypt(s1)
        c = self.encrypt(s2)
        return fraction_mod(self.magic((a, b, c)), self.f.denominator) == r

    @staticmethod
    def magic(ar):
        a, b, c = ar
        return Fraction(a, b) + Fraction(b, c) + Fraction(c, a)


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


f = PublicKey.magic(pub)
e = f.numerator
n = f.denominator
p, q, r = derive_private_key(pub)
assert p * q * r == n
print(p, q, r)
phi = (p - 1) * (q - 1) * (r - 1)
d = pow(e, -1, phi)
s1ps2 = pow(mix[0], d, n)
s1ms2 = pow(mix[1], d, n)
i2 = pow(2, -1, n)
s1 = (s1ps2 + s1ms2) * i2 % n
s2 = (s1ps2 - s1ms2) * i2 % n
r = pow(s1, e, n)
c = pow(s2, e, n)

P = QQ["a, b"]
a, b = P.gens()
"""
a*b^2 + a^2*c + b*c^2 = x*a*b*c (mod n)
(a*b^2 + a^2*c + b*c^2)/(a*b*c) = r = x (mod n)
x/y = r (mod n)
x, y are small -> LLL
g = gcd(x, y) != 1 -> bruteforce
"""

B = matrix(ZZ, [[r, 1], [n, 0]])
B = B.LLL()
x, y = map(abs, B[0])
assert x * pow(y, -1, n) % n == r
for g in range(1, 100):
    xx, yy = x * g, y * g
    I = P.ideal([
        a * b**2 + a**2 * c + b * c**2 - xx,
        a * b * c - yy,
    ])
    try:
        sol = I.variety()[0]
        print(sol)
        print(g, long_to_bytes(int(sol[a])))
        break
    except IndexError:
        pass
