import sys

inp, outp = sys.argv[1:3]
with open(inp, 'rb') as inp, open(outp, 'w') as outp:
    outp.write("unsigned char __[] = {");
    for byte in inp.read():
        byte ^= 0x37
        outp.write(f"{byte:#02x},")
    outp.write("};\n")

