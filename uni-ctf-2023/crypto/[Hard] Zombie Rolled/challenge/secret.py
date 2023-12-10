from sage.all import *

FLAG = b"HTB{4_s3cur3_crypt0syst3m_sh0u1d_n0t_c0nt41n_s3cr3t_c0mp0n3nts!}"

def derive_public_key(priv):
    p, q, r = map(ZZ, priv)
    rhs = p / q + q / r + r / p
    P = QQ["a, b, c"]
    a, b, c = P.gens()
    eq = a / b + b / c + c / a - rhs
    f = EllipticCurve_from_cubic(eq.numerator(), [2, 0, 0])
    fi = f.inverse()
    G = f([p, q, r])
    aa, bb, cc = fi(2 * G)
    l = lcm(lcm(aa.denom(), bb.denom()), cc.denom())
    aa, bb, cc = ZZ(aa * l), ZZ(bb * l), ZZ(cc * l)
    assert aa / bb + bb / cc + cc / aa == rhs
    return int(aa), int(bb), int(cc)
