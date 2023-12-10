#!/usr/bin/env python3

from pwn import *
import struct

core = Corefile("./core")
for mem in core.mappings:
    if mem.name == '':
        heap = mem
        break
else:
    log.error("heap not found")
    exit()

for mem in core.mappings:
    if 'flag' in mem.name:
        flag = mem
        break
else:
    log.error("flag not found")
    exit()


shuffled_flag = core.read(flag.start, 256).decode()
h_pos = shuffled_flag.index('H')
log.info(f"`H` is at {h_pos}")

for addr in range(heap.start, heap.stop, 16):
    ptr, pos, char = struct.unpack("PBB", core.read(addr, 10))
    if ptr in heap and pos == h_pos and char == 0:
        list_head = addr
        break
else:
    log.error("list not found")
    exit()

log.info(f"List head at {list_head:#x}")

flag = ""
while addr:
    addr, pos = struct.unpack("PB", core.read(addr, 9))
    flag += shuffled_flag[pos]
print(f"Flag is: `{flag.strip()}`")
