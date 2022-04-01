from os import urandom
import random
import time
import string
from binascii import hexlify
from cryptography.hazmat.primitives.ciphers import Cipher , algorithms , modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from numpy import std
from statistics import mean
from math import sqrt



NUMBER_OF_FILES = 10


def AES(numBytes):
    timeList = []
    for i in range(NUMBER_OF_FILES):
        message = bytes(GenerateContent(numBytes), 'utf-8')

        start = time.time()

        #Encrypt the content
        key = urandom (32)
        iv = urandom(16)

        cipher = Cipher(algorithms.AES(key),modes.CTR(iv))
        encryptor=cipher.encryptor()

        ct = encryptor.update (message) + encryptor.finalize()

        end = time.time()
        timeList.append(end-start)
    
    return timeList

def RSA(numBytes):
    timeList = []
    for i in range(NUMBER_OF_FILES):
        #Encrypt the content
        message = bytes(GenerateContent(numBytes), 'utf-8')
        
        start = time.time()
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        end = time.time()
        timeList.append(end-start)

    return timeList


def SHA256(numBytes):
    timeList = []    
    for i in range(NUMBER_OF_FILES):
        message = GenerateContent(numBytes)
        start = time.time()

        digest = hashes.Hash(hashes.SHA256())
        digest.update(bytes(message, 'utf-8'))
        digest.finalize()

        end = time.time()
        timeList.append(end-start)
    
    return timeList
    
def PrintConfidenceLevel(numBytes, timeList):
    sd = std(timeList)
    conf_level = 1.96 * (sd/sqrt(NUMBER_OF_FILES))
    print("Intervalo de confiança a 95% para " + str(numBytes) + "\n" + str(mean(timeList)) + " +- " + str(conf_level))

def GenerateContent(numBytes):
    content = ""
    for i in range(numBytes):
        content += str(random.choice(string.ascii_letters))
    return content

l = [8, 64, 512, 4096, 32768, 262144, 2047152]
for i in l:
   PrintConfidenceLevel(i, AES(i))
