from Crypto.Util.number import getPrime, bytes_to_long
from secret import FLAG

class Crypto:
    def __init__(self, bits):
        self.bits = bits
        self.alpha = 1/9
        self.delta = 1/4
        self.known = int(self.bits*self.delta)
    
    def keygen(self):
        while True:
            p, q = [getPrime(self.bits//2) for _ in '__']
            self.e = getPrime(int(self.bits*self.alpha))
            φ = (p-1)*(q-1)
            try:
                dp = pow(self.e, -1, p-1)
                dq = pow(self.e, -1, q-1)
                self.n = p*q
                break
            except:
                pass

        return (self.n, self.e), (dp, dq)

    def encrypt(self, m):
        return pow(m, self.e, self.n)

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
