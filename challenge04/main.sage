import secrets

# Arbitrary upper bound
MAX_SHARES = 32

# Order of secp256k1 elliptic curve
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
R.<x> = PolynomialRing(FiniteField(p))

def sss_get_shares(D, k, n):
    """
    Splits the secret value D into n shares; k of n are needed
    to reconstruct the secret.

    D - 256-bit integer in [0, p)
    """
    assert 0 <= D < p
    assert 1 < k <= n <= MAX_SHARES

    # construct randome polynomial (degree = k-1)
    q = D
    for i in range(1, k):
        a_i = secrets.randbelow(int(p))
        q += a_i * x^i

    return [(i, q(i)) for i in range(1, n + 1)]

def _eval_lagrange_interpolate(t, xs, ys):
    """
    Evaluates the iterpolated polynomial (uses lagrange basis 
    function) at point x.
    t  - 256-bit integer in [0, p)
    xs - list - x co-ordinate of the shares
    ys - list - y co-ordinate of the shares
    """
    # Algorithm
    # 1. calc sum(y_i * delta_{j,x_i}) mod p, i = 0,1..k-1
    # 2. delta_{j,x_i} = {(x -x0).(x -x1)...(x -x_k-1)/
    #                     (xi-x0).(xi-x1)...(xi-x_k-1)} mod p
    poly = R(0)
    for i in range(len(ys)):
        delta = R(1)
        x_i = xs[i]
        y_i = ys[i]
        for x_j in xs:
            if(x_j == x_i): 
                continue
            delta = delta*((x - x_j)/(x_i - x_j))
        poly += y_i*delta

    return poly(t)


def sss_recover_secret(shares):
    """
    Recovers the secret D from the given shares.

    shares - list of points (x_i, y_i) on the polynomial
    """
    # Algorithm
    # 1. assert for distinct x_i
    # 2. evaluate the polynomial at 0
    xs = [share[0] for share in shares]
    ys = [share[1] for share in shares]
    assert len(xs) == len(set(xs))

    return _eval_lagrange_interpolate(0, xs, ys)

if __name__ == '__main__':

    # Initialize share values
    shares = list()
    shares.append((1, 0xB4EB3F62388EA2343FFC28BB342D4245E9C8B3B0602825235460DD74F0D47AB1))
    shares.append((3, 0xBE3A9EC4C3D5FA291CAFBB54C5F0301F29FE14539575408B57F3CF6C0EA6399E))
    shares.append((4, 0x760E31377BF2240AD9DA8A9843FF4B27A0D42F66DF029BF06A8F584FA008EA4D))

    secret = int(sss_recover_secret(shares)).to_bytes(32, "big")
    print(secret)

    