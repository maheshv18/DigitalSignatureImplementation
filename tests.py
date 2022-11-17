import unittest
from math import gcd
from random import randint
from Crypto.Util.number import isPrime
import rsa_signature as rsa


class TestInternalFunctions(unittest.TestCase):
    def test_primes(self):
        """
        Check if numbers used in keys generation are actually prime.
        """

        # generate primes for testing
        (_, _), _, (p, q) = rsa.generate_keys(return_primes=True)

        # test with PyCryptodome's implementation of Miller-Rabin test
        self.assertTrue(isPrime(p))
        self.assertTrue(isPrime(q))

    def test_public_exponent(self):
        """
        Check if public exponent e and phi are coprime numbers.
        """

        # generate public expontent for testing and calculate phi
        (_, e), _, (p, q) = rsa.generate_keys(return_primes=True)
        phi = (p - 1) * (q - 1)

        # test with gcd() function from standard math module
        self.assertTrue(gcd(e, phi))

    def test_extended_euclidean(self):
        """
        Test whether coefficients of Bézouts identity are valid
        and equation ax + by = gcd(a, b) is fulfilled.
        """

        # generate two random integers to check
        a = randint(10, 1000)
        b = randint(10, 1000)

        # calculate Bézouts coefficients
        _, x, y = rsa.extended_euclidean(a, b)

        # calculate ax + by
        equation_result = a * x + b * y

        # test with gcd() function from standard math module
        self.assertEqual(equation_result, gcd(a, b))


class TestSigning(unittest.TestCase):
    def test_signing_and_verifying(self):
        """
        Test if generated signature for a given message can be verified correctly for different sizes of key.
        """

        # message for all tests
        message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

        # 512-bit key
        (n_512, e_512), d_512 = rsa.generate_keys(512)
        s_512 = rsa.generate_signature(message, n_512, e_512, d_512)

        # 1024-bit key
        (n_1024, e_1024), d_1024 = rsa.generate_keys(1024)
        s_1024 = rsa.generate_signature(message, n_1024, e_1024, d_1024)

        # 2048-bit key
        (n_2048, e_2048), d_2048 = rsa.generate_keys()
        s_2048 = rsa.generate_signature(message, n_2048, e_2048, d_2048)

        # 4096-bit key
        (n_4096, e_4096), d_4096 = rsa.generate_keys(4096)
        s_4096 = rsa.generate_signature(message, n_4096, e_4096, d_4096)

        self.assertTrue(rsa.verify(message, n_512, e_512, s_512))
        self.assertTrue(rsa.verify(message, n_1024, e_1024, s_1024))
        self.assertTrue(rsa.verify(message, n_2048, e_2048, s_2048))
        self.assertTrue(rsa.verify(message, n_4096, e_4096, s_4096))

    def test_invalid_cases(self):
        """
        Test cases when signature verification is not passed.
        """

        # generate signature for a message
        message = "Sample message"
        (n, e), d = rsa.generate_keys()
        s = rsa.generate_signature(message, n, e, d)

        # verify signature for another message
        message2 = "Another message"
        self.assertFalse(rsa.verify(message2, n, e, s))

        # verify the same signature for another public key
        (n, e), d = rsa.generate_keys()
        self.assertFalse(rsa.verify(message, n, e, s))
