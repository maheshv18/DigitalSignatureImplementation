from math import gcd
from hashlib import sha512
from random import randrange, getrandbits
from typing import Union


def is_prime(n: int, k: int) -> bool:
    """
    The function implements the Miller-Rabin primality test.

    Input:
    n - the number to be tested
    k - number of tests to be performed

    Output: a boolean value
    """

    # trivial cases: 0-2 and even numbers
    if n == 2:
        return True
    elif n <= 1 or n % 2 == 0:
        return False

    # writing n as 2^r * d + 1 with d odd
    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    # perform k number of tests
    for _ in range(k):
        a = randrange(2, n - 2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime_number(prime_size:int) -> int:
    """
    Generates large prime numbers.

    Input: prime_size - size of prime number expressed in number of bits

    Output: p - a large prime number
    """

    p = 0

    # choose randomly a large number until prime is obtained
    while not is_prime(p, 180):
        p = getrandbits(prime_size)

    return p


def extended_euclidean(a: int, b: int) -> tuple[int, int, int]:
    """
    Computes greatest common divisor and the coefficients of Bézout's identity.

    Input: a, b - non-negative integers satisfying a >= b

    Output: gcd  - greatest common divisor
            x, y - the coefficients of Bézout's identity
    """

    if b == 0:
        return (a, 1, 0)

    x1, x2, y1, y2 = 0, 1, 1, 0
    while b > 0:
        q, r = divmod(a, b)
        x = x2 - q * x1
        y = y2 - q * y1

        a, b, x2, x1, y2, y1 = b, r, x1, x, y1, y

    gcd, x, y = a, x2, y2
    return (gcd, x, y)


def generate_keys(key_size:int = 2048, return_primes: bool = False) -> Union[tuple[int, int, int], tuple[int, int, int, int, int]]:
    """
    Generates RSA public and private keys.

    Input: key_size - size of the key expressed in number of bits (2048 bits by default)
           return_prime - if set, function returns additionaly tuple of prime numbers p and q used in key generation

    Output: (n, e) - public key
                 d - private key
            (p, q) - primes used in generation (optional)
    """

    # generate two large random primes
    p = generate_prime_number(key_size // 2)
    q = generate_prime_number(key_size // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    # find such e, that e and phi are coprimes
    e = 0
    while gcd(e, phi) != 1:
        e = randrange(1 + 1, phi - 1)

    # find modular multiplicative inverse
    _, x, _ = extended_euclidean(e, phi)
    d = x + phi

    # return public and private keys (optionally primes p and q)
    if return_primes:
        return ((n, e), d, (p, q))
    else:
        return ((n, e), d)


def generate_signature(m, n: int, e: int, d: int) -> int:
    """
    The function generates an RSA digital signature.

    Input:
    m - message
    n, e - public key of sender
    d - private key of sender

    Output:
    a digital signature s

    """
    # compute hash of message
    h = int(sha512(m.encode("utf-8")).hexdigest(), 16) % 10 ** 8

    # compute signature and return it
    s = pow(h, d, n)
    return s


def verify(m, n: int, e: int, s: int) -> bool:
    """
    The function generates verifies the received signature using public key.

    Input:
    (n,e) - public key of sender
    s - digital signature

    Output:
    a boolean value

    """
    # decrypt the message
    h_ = pow(s, e, n)

    # calculate message hash
    h = int(sha512(m.encode("utf-8")).hexdigest(), 16) % 10 ** 8

    # compare and return
    return h_ == h
