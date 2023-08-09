import random
import math

# This function returns the largest shared divider between a and b
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# This function returns if the num is a prime number or not
def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(math.sqrt(num)) + 1):
        if num % i == 0:
            return False
    return True

# This function generates a new nubmer and checks if it's a prime,
# it does so until the function gets a prime number which is then returned
def generate_prime():
    while True:
        p = random.randint(int(math.pow(2, 5)), int(math.pow(2, 6)))
        if is_prime(p):
            return p

# This function generates keypair - public and private keys of RSA encryption method
def generate_keypair():
    p = generate_prime()
    q = generate_prime()
    while q == p:
        q = generate_prime()
    n = p * q
    phi = (p-1) * (q-1)
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    d = multiplicative_inverse(e, phi)
    return (e, n), (d, n)

# This function returns the reminder of the first number divided by the second number
# in order to get the completion for the key pairs(public and private keys)
def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi

    while e > 0:
        temp1 = temp_phi//e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2

        x = x2- temp1* x1
        y = d - temp1 * y1

        x2 = x1
        x1 = x
        d = y1
        y1 = y

    if temp_phi == 1:
        return d % phi
    else:
        return None

# This class contains the functions that can be accessed outside of the file
class RSAEncryption:
    def __init__(self):
        self.public_key = None
        self.private_key = None

    # This function uses the generate_keypair function to get the keys(public and private)
    # and then saves them in the variables public_key and private_key
    def generate_keypair(self):
        self.public_key, self.private_key = generate_keypair()

    # This function returns the objects' public key
    def get_public_key(self):
        return self.public_key

    # This function returns the objects' private key 
    def get_private_key(self):
        return self.private_key

    # This function sets the objects' private key
    def set_private_key(self, private_key):
        self.private_key = private_key

    # This function sets the objects' public key
    def set_public_key(self, public_key):
        self.public_key = public_key

    # This function gets a key and text and then encrypts it using the key it got and then returns it
    def encrypt_RSA(self, pk, plaintext):
        key, n = pk
        if isinstance(plaintext, str):
            cipher = [(pow(ord(char), key, n)) for char in plaintext]
        else:
            cipher = [(pow(int(plaintext), key, n))]
        return cipher

    # This fucntion gets a key and encrypted text and then decrypts it using the key it got and then returns it
    def decrypt_RSA(self, pk, ciphertext):
        key, n = pk
        plain = [chr(int(pow(char, key, n))) for char in ciphertext]
        return ''.join(plain)

    # Function takes a message and encrypts it using the RSA encryption created here
    def encrypt_message(self, message):
        if self.public_key is None:
            raise ValueError("Public key not set. Please generate keypair first.")
        ciphertext = self.encrypt_RSA(self.public_key, message)
        return ciphertext

    # Function takes a message and decrypts it using the RSA encryption created here
    def decrypt_message(self, ciphertext):
        if self.private_key is None:
            raise ValueError("Private key not set. Please generate keypair first.")
        plaintext = self.decrypt_RSA(self.private_key, ciphertext)
        return plaintext
