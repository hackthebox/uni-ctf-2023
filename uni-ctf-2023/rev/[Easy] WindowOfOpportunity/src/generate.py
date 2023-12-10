#!/usr/bin/env python3

flag = b"HTB{4_d00r_cl0s35_bu7_4_w1nd0w_0p3n5!}"
bs = [(flag[i] + flag[i+1]) & 0xff for i in range(len(flag)-1)]
print("#define SUMS {" + ",".join(hex(x) for x in bs) + "}")
