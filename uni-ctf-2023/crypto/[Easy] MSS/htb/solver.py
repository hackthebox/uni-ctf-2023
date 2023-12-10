from pwn import remote, process, args
from sympy.ntheory.modular import crt
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import json, math
from hashlib import sha256


if args.REMOTE:
    ip, port = args.HOST.split(":")
    io = remote(ip, int(port))
else:
    io = process("python3 ../challenge/server.py", shell=True)

d = 30
n = 19

X = [getPrime(15) for _ in range(n-1)]
RK = [] # reduced keys

for x in X:
    payload = json.dumps({'command': 'get_share', 'x': x})
    io.sendlineafter(b'query = ', payload.encode())
    y = json.loads(io.recvline().strip())['y']
    RK.append(y % x)

key = int(crt(X, RK)[0])
key = sha256(str(key).encode()).digest()

payload = json.dumps({'command': 'encrypt_flag'})
io.sendlineafter(b'query = ', payload.encode())
io.recvuntil(b'flag : ')

data = json.loads(io.recvuntil(b'}').strip())
iv = bytes.fromhex(data['iv'])
encflag = bytes.fromhex(data['enc_flag'])

cipher = AES.new(key, AES.MODE_CBC, iv)

print(unpad(cipher.decrypt(encflag), 16).decode())

