"""Just enough edwards25519 in pure Python to build edge-case keys and signatures for the differential tests:
small-order points, non-canonical encodings, mixed-order keys.  Not used for any verdict (pyca decides those)."""

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def inv(x):
    return pow(x, P - 2, P)


def add(a, b):
    (x1, y1), (x2, y2) = a, b
    t = D * x1 * x2 * y1 * y2 % P
    return ((x1 * y2 + x2 * y1) * inv(1 + t) % P, (y1 * y2 + x1 * x2) * inv(1 - t) % P)


def mul(k, p):
    r = (0, 1)
    while k:
        if k & 1:
            r = add(r, p)
        p = add(p, p)
        k >>= 1
    return r


def recover_x(y, sign):
    """x for y (any integer, reduced mod p), or None."""
    y %= P
    xx = (y * y - 1) * inv(D * y * y + 1) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * SQRT_M1 % P
    if (x * x - xx) % P:
        return None
    if x == 0 and sign:
        return None
    return P - x if x & 1 != sign else x


def encode(p, y_add=0, sign_flip=False):
    """Encoding of p; y_add=P gives the non-canonical y + p (where it fits in 255 bits), sign_flip the other sign."""
    x, y = p
    v = (y + y_add) | ((x & 1) ^ sign_flip) << 255
    return v.to_bytes(32, "little")


def decode(b):
    v = int.from_bytes(b, "little")
    y, sign = v & ((1 << 255) - 1), v >> 255
    x = recover_x(y, sign)
    return None if x is None else (x, y % P)


BY = 4 * inv(5) % P
B = (recover_x(BY, 0), BY)


def small_order_points():
    """The 8 points of the torsion subgroup."""
    pts = {(0, 1)}
    y = 2
    while len(pts) < 8:
        x = recover_x(y, 0)
        if x is not None:
            t = mul(L, (x, y))  # the torsion component of a random point
            for k in range(8):
                pts.add(mul(k, t))
        y += 1
    return sorted(pts)


def h(*parts):
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def sign_with(a, A_enc, msg, r=7):
    """A signature (R, S) with scalar a over a given public-key encoding A_enc (which may carry torsion)."""
    R = mul(r, B)
    Re = encode(R)
    k = h(Re, A_enc, msg) % L
    S = (r + k * a) % L
    return Re + S.to_bytes(32, "little"), k
