from Crypto.Util.number import long_to_bytes as l2b

with open('output.txt') as f:
    exec(f.readline())
    exec(f.readline())
    exec(f.readline())
    dp_msb = eval(f.readline().split(' = ')[1].strip())
    dq_msb = eval(f.readline().split(' = ')[1].strip())

BITS = 2048
alpha = 1/9
delta = 1/4
KNOWN_BITS = int(BITS*delta)
i = BITS//2 - KNOWN_BITS

A = ceil(((2**(2*i) * e**2 * dp_msb * dq_msb) / N))  # A = k*l

k_plus_l = (1-A*(N-1)) % e

k, l = var('k,l', domain=ZZ)

for s in [k_plus_l, k_plus_l + e]:
	try:
		sol = solve([k*l == A, k+l == s], k, l, solution_dict=True)[0]
		k, l = int(sol[k]), int(sol[l])
		break
	except:
		pass

print(f'[+] {k = }')
print(f'[+] {l = }')

assert A == k*l

# we found k,l but probably in the wrong order
# try both
for kt, _ in [[k, l], [l, k]]:
	try:
		x = PolynomialRing(Zmod(kt*N), 'x').gens()[0]

		F = x + (e*dp_msb*2**i + kt - 1) * pow(e, -1, kt*N)

		dp_lsb = int(F.small_roots(X=2**i, beta=0.5)[0])

		print(f'[+] {dp_lsb = }')

		dp = (dp_msb << i) + dp_lsb

		p = (e*dp+kt-1) // kt
		q = N // p

		assert N == p * q

		print(f'[+] {p = }')
		print(f'[+] {q = }')

		phi = (p-1)*(q-1)
		d = pow(e, -1, phi)
		m = pow(c, d, N)

		print(l2b(m))
	except:
		pass

