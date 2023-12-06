import random
import hashlib
from math import sqrt
        
def generate_prime(bits):

    return 2**(bits - 1) + random.getrandbits(bits - 1)


def isPrime( n): 
 

    if (n <= 1):
        return False
    if (n <= 3):
        return True
 

    if (n % 2 == 0 or n % 3 == 0):
        return False
    i = 5
    while(i * i <= n):
        if (n % i == 0 or n % (i + 2) == 0) :
            return False
        i = i + 6
 
    return True

def power( x, y, p): 
 
    res = 1 
 
    x = x % p 
 
    while (y > 0): 
 
        if (y & 1):
            res = (res * x) % p 
 
        y = y >> 1
        x = (x * x) % p 
 
    return res 
 

def findPrimefactors(s, n) :
 

    while (n % 2 == 0) :
        s.add(2) 
        n = n // 2
 

    for i in range(3, int(sqrt(n)), 2):
         
        while (n % i == 0) :
 
            s.add(i) 
            n = n // i 
         
    if (n > 2) :
        s.add(n) 
 
def findPrimitive( n) :
    s = set() 
 
    if (isPrime(n) == False): 
        return -1
 
    phi = n - 1
 
    findPrimefactors(s, phi) 
 
    for r in range(2, phi + 1): 
 
        flag = False
        for it in s: 
 
            if (power(r, phi // it, n) == 1): 
 
                flag = True
                break
             
        if (flag == False):
            return r 
 
    return -1

def generate_keys(p_bits):
    p = generate_prime(p_bits)
    g = findPrimitive(p)
    a = random.randint(1, p - 1)
    b = pow(g, a, p)
    public_key = (p, g, b)
    private_key = a
    return public_key, private_key

def hash_message(message):
    sha256 = hashlib.sha256()
    sha256.update(message.encode())
    return int(sha256.hexdigest(), 16)

def sign(message, private_key, public_key):
    p, g, b = public_key
    h = hash_message(message)
    
    k = random.randint(1, p - 1)
    r = pow(g, k, p)
    
    k_inv = pow(k, -1, p - 1)
    s = (k_inv * (h - private_key * r)) % (p - 1)
    
    return r, s

def verify(message, signature, public_key):
    p, g, b = public_key
    r, s = signature
    
    y = pow(b, -1, p)
    h = hash_message(message)
    
    u1 = (h * pow(s, -1, p - 1)) % (p - 1)
    u2 = (r * pow(s, -1, p - 1)) % (p - 1)
    
    v = (pow(g, u1, p) * pow(y, u2, p)) % p
    
    return v == r

def encrypt(message, public_key):
    p, g, b = public_key
    
    m = int.from_bytes(message.encode(), 'big')
    k = random.randint(1, p - 1)
    
    x = pow(g, k, p)
    y = (pow(b, k, p) * m) % p
    
    return x, y

def decrypt(ciphertext, private_key, public_key):
    p, _, _ = public_key
    x, y = ciphertext
    
    s = pow(x, private_key, p)
    s_inv = pow(s, -1, p)
    
    m = (y * s_inv) % p
    
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()

# Перевірка функції підпису
def test_signature_verification():
    message = "Hello, world! This is my implementation of Elgamal. Made by Kyryl Kitsun"

    signature = sign(message, private_key_sign, public_key_sign)
    is_valid = verify(message, signature, public_key_sign)

    print("\nSignature Validation:")
    print("Original Message:", message)
    print("Signature:", signature)
    print("Is Valid Signature?", is_valid)

    modified_message = "Goodbye World! This is modified message, validation should return false"
    is_valid_modified = verify(modified_message, signature, public_key_sign)
    print("\nModified Message Validation:")
    print("Modified Message:", modified_message)
    print("Is Valid Signature?", is_valid_modified)

# Перевірка спрямованого шифрування
def test_encryption_verification():
    message = "Hello, world! This is my implementation of Elgamal. Made by Kyryl Kitsun"

    ciphertext = encrypt(message, public_key_encrypt)
    decrypted_message = decrypt(ciphertext, private_key_encrypt, public_key_encrypt)

    print("\nEncryption test:")
    print("Original Message:", message)
    print("Encrypted Message:", ciphertext)
    print("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    public_key_sign, private_key_sign = generate_keys(2048)
    public_key_encrypt, private_key_encrypt = generate_keys(2048)

    test_signature_verification()
    test_encryption_verification()
