import os, random, json
from hashlib import sha256
from Crypto.Util.number import bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secret import FLAG


class MSS:
    def __init__(self, BITS, d, n):
        self.d = d
        self.n = n
        self.BITS = BITS
        self.key = bytes_to_long(os.urandom(BITS//8))
        self.coeffs = [self.key] + [bytes_to_long(os.urandom(self.BITS//8)) for _ in range(self.d)]

    def poly(self, x):
        return sum([self.coeffs[i] * x**i for i in range(self.d+1)])

    def get_share(self, x):
        if x < 1 or x > 2**15:
            return {'approved': 'False', 'reason': 'This scheme is intended for less users.'}
        elif self.n < 1:
            return {'approved': 'False', 'reason': 'Enough shares for today.'}
        else:
            self.n -= 1
            return {'approved': 'True', 'x': x, 'y': self.poly(x)}
    
    def encrypt_flag(self, m):
        key = sha256(str(self.key).encode()).digest()
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(m, 16))
        return {'iv': iv.hex(), 'enc_flag': ct.hex()}

def show_banner():
    print("""
#     #  #####   #####               #       ###   
##   ## #     # #     #             ##      #   #  
# # # # #       #                  # #     #     # 
#  #  #  #####   #####     #    #    #     #     # 
#     #       #       #    #    #    #     #     # 
#     # #     # #     #     #  #     #   ## #   #  
#     #  #####   #####       ##    ##### ##  ###

This is a secure secret sharing scheme with really small threshold. We are pretty sure the key is secure...
    """)

def show_menu():
    return """
Send in JSON format any of the following commands.

    - Get your share
    - Encrypt flag
    - Exit

query = """


def main():
    mss = MSS(256, 30, 19)
    show_banner()
    while True:
        try:
            query = json.loads(input(show_menu()))
            if 'command' in query:
                cmd = query['command']
                if cmd == 'get_share':
                    if 'x' in query:
                        x = int(query['x'])
                        share = mss.get_share(x)
                        print(json.dumps(share))
                    else:
                        print('\n[-] Please send your user ID.')
                elif cmd == 'encrypt_flag':
                    enc_flag = mss.encrypt_flag(FLAG)
                    print(f'\n[+] Here is your encrypted flag : {json.dumps(enc_flag)}.')
                elif cmd == 'exit':
                    print('\n[+] Thank you for using our service. Bye! :)')
                    break
                else:
                    print('\n[-] Unknown command:(')
        except KeyboardInterrupt:
            exit(0)
        except (ValueError, TypeError) as error:
            print(error)
            print('\n[-] Make sure your JSON query is properly formatted.')
            pass

if __name__ == '__main__':
    main()
