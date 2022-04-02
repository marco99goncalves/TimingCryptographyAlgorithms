from os import urandom
import random
import time
import string
from binascii import hexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from numpy import std
from statistics import mean
from math import sqrt


NUMBER_OF_FILES = 100


def AES(numBytes):
    encTime = []
    decTime = []
    for i in range(NUMBER_OF_FILES):
        message = bytes(GenerateContent(numBytes), 'utf-8')

        # Encrypt the content
        key = urandom(32)
        iv = urandom(16)

        start = time.time()
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        encryptor = cipher.encryptor()

        ct = encryptor.update(message) + encryptor.finalize()

        end = time.time()
        encTime.append((end-start)*1000000)

        # Decrypt
        start = time.time()

        # Codigo de desencriptação
        plaintext = Cipher(algorithms.AES(key), modes.CTR(iv))
        decryptor = cipher.encryptor()

        pt = decryptor.update(ct) + decryptor.finalize()

        end = time.time()
        decTime.append((end-start)*1000000)

    return (encTime, decTime)


def SHA256(numBytes):
    encTime = []
    decTime = []
    for i in range(NUMBER_OF_FILES):
        message = bytes(GenerateContent(numBytes), 'utf-8')
        start = time.time()

        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        digest.finalize()

        end = time.time()
        encTime.append((end-start)*1000000)

    return (encTime, decTime)


def RSA(numBytes):
    encTime = []
    decTime = []
    for i in range(NUMBER_OF_FILES):
        # Encrypt the content
        message = bytes(GenerateContent(numBytes), 'utf-8')

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        start = time.time()
        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        end = time.time()
        encTime.append((end-start)*1000000)

        # Decrypt
        start = time.time()

        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        end = time.time()
        decTime.append((end-start)*1000000)

    return (encTime, decTime)


def PrintConfidenceLevel(numBytes, encTime, decTime):
    # Intervalo de confiança para encriptação
    sd = std(encTime)
    conf_level = 1.96 * (sd/sqrt(NUMBER_OF_FILES))
    #print("-------------- " + str(numBytes) + " bytes --------------")
    print(str(mean(encTime)) + " " + str(conf_level))

    #if(len(decTime) > 0):
        # Intervalo de confiança para desencriptação
        #sd = std(decTime)
        #conf_level = 1.96 * (sd/sqrt(NUMBER_OF_FILES))
        #print(str(mean(decTime)) + " +- " + str(conf_level))
        # print("----------------------------------------\n")


def GenerateContent(numBytes):
    content = ""
    for i in range(numBytes):
        content += str(random.choice(string.ascii_letters))
    return content


l = [8, 8, 64, 512, 4096, 32768, 262144, 2047152]
for i in l:
    encTime, decTime = AES(i)
    PrintConfidenceLevel(i, encTime, decTime)
