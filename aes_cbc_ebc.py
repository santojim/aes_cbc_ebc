#!/usr/bin/python3

from Crypto import Random
from Crypto.Cipher import AES
from shutil import copyfile
import os
import os.path
from os import listdir
from os.path import isfile, join
import time
import getopt
import sys

class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        with open(file_name + ".cbc", 'wb') as fo:
            fo.write(enc)
        with open(file_name + ".cbc_binary_form", 'w+') as fo:
            fo.write(''.join('{0:08b}'.format(i,'b')for i in enc))
        os.remove(file_name)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

    def encrypt_ecb(self, message, key, key_size=256):
        message = self.pad(message)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(message)

    def encrypt_ecb_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt_ecb(plaintext, self.key)
        with open(file_name[:-4] + ".ecb", 'wb') as fo:
            fo.write(enc)
        with open(file_name[:-4] + ".ecb_binary_form", 'w+') as fo:
            fo.write(''.join('{0:08b}'.format(i,'b')for i in enc))
        os.remove(file_name)

    def decrypt_ecb(self, ciphertext, key):
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.rstrip(b"\0")

    def decrypt_ecb_file(self, file_name):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt_ecb(ciphertext, self.key)
        with open(file_name[:-4] +".from_ecb", 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

def main(argv):

	key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'
	enc = Encryptor(key)

	inputfile = ''
	encrypt_flag = 0
	decrypt_flag = 0
	try:
		opts, args = getopt.getopt(argv,"hi:ed",["ifile=","ofile="])
	except getopt.GetoptError:
		print ('test.py -i <inputfile> -e [encrypt] -d [decrypt]')
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print ('test.py -i <inputfile> -e [encrypt] -d [decrypt]')
			sys.exit()
		elif opt in ("-i", "--ifile"):
			inputfile = arg
		elif opt in ("-e"):
			encrypt_flag = 1
		elif opt in ("-d"):
			decrypt_flag = 1
	print ('Input file is :', inputfile)
	if encrypt_flag == 1:
		print("will encrypt")
		copyfile(inputfile,inputfile+"copy" )
		enc.encrypt_file(inputfile)
		enc.encrypt_ecb_file(inputfile+"copy")
	if decrypt_flag == 1:
		print("will decrypt")
		enc.decrypt_file(inputfile+".cbc")
		enc.decrypt_ecb_file(inputfile+".ecb")

if __name__ == "__main__":
   main(sys.argv[1:])
