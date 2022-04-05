from os import urandom
import sys
import random
import time
import string
import matplotlib.pyplot as plt
from binascii import hexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from numpy import std, percentile
from statistics import mean, median
from math import sqrt

OFFSET = 100
NUMBER_OF_FILES = 1000+OFFSET


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
    # Dados para encriptação

    encTime = encTime[-(int(NUMBER_OF_FILES/2)):]
    encTime.sort()
    q3, q1 = percentile(encTime, [75, 25])
    iqr = q3 - q1
    print(str(median(encTime)) + " " + str(iqr))


def SimplePlot(x, y, y_err, file_name, plot_label):
    plt.errorbar(x, y, y_err, marker="o", label=plot_label + " Encryption")
    plt.xscale('log', base=2)
    plt.xticks(x, labels=x)
    plt.ylabel("Time (Microseconds)")
    plt.xlabel("Plaintext size (Bytes)")

    plt.title(plot_label + " Times")
    plt.legend()

    for xs, ys in zip(x, y):

        label = "{:.2f}".format(ys)

        plt.annotate(label,  # this is the text
                     (xs, ys),  # these are the coordinates to position the label
                     textcoords="offset points",  # how to position the text
                     xytext=(0, 10),  # distance from text to points (x,y)
                     ha='center')  # horizontal alignment can be left, right or center

    plt.savefig(file_name)


def SimplePlotWithDec(x, y_enc, y_enc_err, y_dec, y_dec_err, file_name, plot_label):
    plt.errorbar(x, y_enc, y_enc_err, marker="o",
                 label=plot_label + " Encryption")
    plt.errorbar(x, y_dec, y_dec_err, marker="o",
                 label=plot_label + " Decryption")
    plt.xscale('log', base=2)
    plt.xticks(x, labels=x)
    plt.ylabel("Time (Microseconds)")
    plt.xlabel("Plaintext size (Bytes)")

    plt.title(plot_label + " Times")
    plt.legend(loc='center left', bbox_to_anchor=(1, 0.5))

    for xs, ys in zip(x, y_enc):

        label = "{:.2f}".format(ys)

        plt.annotate(label,  # this is the text
                     (xs, ys),  # these are the coordinates to position the label
                     textcoords="offset points",  # how to position the text
                     xytext=(0, 10),  # distance from text to points (x,y)
                     ha='center')  # horizontal alignment can be left, right or center

    for xs, ys in zip(x, y_dec):

        label = "{:.2f}".format(ys)

        plt.annotate(label,  # this is the text
                     (xs, ys),  # these are the coordinates to position the label
                     textcoords="offset points",  # how to position the text
                     xytext=(0, 10),  # distance from text to points (x,y)
                     ha='center')  # horizontal alignment can be left, right or center

    plt.savefig(file_name, bbox_inches='tight')


def GenerateContent(numBytes):
    content = ""
    for i in range(numBytes):
        content += str(random.choice(string.ascii_letters))
    return content


# x = [8, 64, 512, 4096, 32768, 262144, 2047152]#AES/SHA
x = [2, 4, 8, 16, 32, 64, 128]  # RSA
y_enc = []
y_enc_err = []

y_dec = []
y_dec_err = []


for i in x:
    encTime, decTime = RSA(i)
    encTime = encTime[-OFFSET:]
    q3, q1 = percentile(encTime, [75, 25])
    encTime.sort()
    iqr_enc = q3 - q1
    y_enc.append(median(encTime))
    y_enc_err.append(iqr_enc)

    decTime = decTime[-OFFSET:]
    q3, q1 = percentile(decTime, [75, 25])
    decTime.sort()
    iqr_dec = q3 - q1
    y_dec.append(median(decTime))
    y_dec_err.append(iqr_dec)

#PrintConfidenceLevel(i, encTime, decTime)
SimplePlotWithDec(x, y_enc, y_enc_err, y_dec,
                  y_dec_err, sys.argv[1], sys.argv[2])
