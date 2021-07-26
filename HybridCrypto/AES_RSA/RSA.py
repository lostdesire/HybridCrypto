import random
import sys

sys.setrecursionlimit(2048)


class RSA:
    # noinspection PyMethodMayBeStatic
    def extended_euclid(self, a, b):

        if a == b:
            return 1, 0, a
        elif b == 0:
            return 1, 0, a
        else:
            x_1 = 1
            y_1 = 0
            r_1 = a

            x_2 = 0
            y_2 = 1
            r_2 = b

            while r_2 != 0:
                q = r_1 // r_2

                r_t = r_1 - q * r_2
                x_t = x_1 - q * x_2
                y_t = y_1 - q * y_2

                x_1, y_1, r_1 = x_2, y_2, r_2
                x_2, y_2, r_2 = x_t, y_t, r_t

            return x_1, y_1, r_1

    # convert an integer to a binary representation
    # noinspection PyMethodMayBeStatic
    def int_to_bin(self, num):
        return list(bin(num))[2:]

    # modular exponentiation
    def exp(self, a, b, n):
        c = 0
        f = 1
        bin_b = self.int_to_bin(b)
        k = len(bin_b)
        for i in range(k):
            c = 2 * c
            f = (f * f) % n
            if bin_b[i] == '1':
                c = c + 1
                f = (f * a) % n
        return f

    # miller_rabin prime test
    Prime = 0
    Composite = 1

    def miller_rabin(self, n, s):
        if n == 2:
            return self.Prime
        elif n % 2 == 0:
            return self.Composite

        for _ in range(s):
            a = random.randint(1, n - 1)
            if self.test(a, n):
                return self.Composite

        return self.Prime

    # subroutine for miller-rabin prime test
    def test(self, a, n):
        bits = self.int_to_bin(n - 1)
        k = len(bits) - 1
        t = 0

        while bits[k] == '0':
            t += 1
            k -= 1

        u = (n - 1) >> t
        x = self.exp(a, u, n)
        for _ in range(t):
            _x = x
            x = (_x * _x) % n
            if x == 1 and _x != 1 and _x != n - 1:
                return True

        if x != 1:
            return True
        else:
            return False

    # RSA key generation
    def keygen(self, keyLen):
        p, q = 0, 0

        prime_len = keyLen // 2

        while p == 0 or q == 0:
            temp = 2 ** (prime_len - 1) + random.randrange(0, 2 ** (prime_len - 1))
            if not self.miller_rabin(temp, 20):
                if p == 0:
                    p = temp
                elif temp != p:
                    q = temp

        n = p * q
        pn = (p - 1) * (q - 1)

        e = 0
        d = 0
        remain = 0

        while remain != 1:
            e = random.randrange(2, pn)
            x, d, remain = self.extended_euclid(pn, e)

            if d < 0:
                d = (d + pn) % pn

        return e, d, n

    # RSA encrypt
    def encrypt(self, M, e, n):
        return self.exp(M, e, n)

    # RSA decrypt
    def decrypt(self, C, d, n):
        return self.exp(C, d, n)


if __name__ == "__main__":
    RSA = RSA()
    encrypt, decrypt, number = RSA.keygen(2048)
    Message = 88
    Cipher = RSA.encrypt(Message, encrypt, number)
    MM = RSA.decrypt(Cipher, decrypt, number)
    if Message == MM:
        print("Example of RSA Algorithm works successfully")
        print("M={}\nPU=({},{})\nPR=({},{})\nC={}\nMM={}".format(Message, encrypt, number, decrypt, number, Cipher, MM))
    else:
        print("Example of RSA Algorithm works failed")
        print("M={}\nPU=({},{})\nPR=({},{})\nC={}\nMM={}".format(Message, encrypt, number, decrypt, number, Cipher, MM))
