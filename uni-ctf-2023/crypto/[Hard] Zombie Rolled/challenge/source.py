from Crypto.Util.number import getPrime, bytes_to_long
from fractions import Fraction
from math import prod
from hashlib import sha256
from secrets import randbelow

# I hope no one cares about Kerckhoff's principle :)
from secret import derive_public_key, FLAG


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


class PrivateKey(PublicKey):

    def __init__(self, priv, pub):
        super().__init__(pub)
        if self.magic(priv) != self.f:
            raise ValueError("Invalid key pair")
        self.priv = priv
        self.d = pow(self.f.numerator, -1, prod([x - 1 for x in priv]))

    def decrypt(self, c):
        return pow(c, self.d, self.f.denominator)

    def sign(self, m):
        h = bytes_to_long(sha256(m.to_bytes(self.nb, "big")).digest())
        a, b = m, h
        c = randbelow(1 << self.nb)
        r = fraction_mod(self.magic((a, b, c)), self.f.denominator)
        s1 = self.decrypt(r)
        s2 = self.decrypt(c)
        return s1, s2

    @staticmethod
    def generate(nbits):
        while True:
            try:
                priv = tuple([getPrime(nbits) for _ in range(3)])
                pub = derive_public_key(priv)
                return PrivateKey(priv, pub)
            except ValueError:
                pass


def main():
    assert len(FLAG) <= 64
    m = bytes_to_long(FLAG)

    key = PrivateKey.generate(1024)
    data = f"pub = {key.pub}\n"

    # make sure it really works
    enc = key.encrypt(m)
    assert key.decrypt(enc) == m
    sig = key.sign(m)
    assert key.verify(m, sig)

    # mixing them :)
    mix = [sig[0] + sig[1], sig[0] - sig[1]]
    mix = [key.encrypt(x) for x in mix]
    data += f"mix = {mix}"

    with open("output.txt", "w") as f:
        f.write(data)


if __name__ == "__main__":
    main()
