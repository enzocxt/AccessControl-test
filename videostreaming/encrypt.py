import os, random, struct, sys
from Crypto.Cipher import AES
import base64, hashlib
# from ContentEncrypt import DataKey

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]

class Key:
	def __init__(self, key = None):
		if key == None:
			self.key = os.urandom(16)
		else:
			self.key = key
	
	def get_key(self):
		if self.key == None:
			print "Alert: No key generated!"
		else:
			return self.key
	def set_key(self, key = None):
		if key == None:
			print "Alert: No argurement!"
		else:
			self.key = key

class AESCipher:
	def __init__(self, key = None):
		self.key = Key(key)
		
	def encrypt(self, raw):
		raw = pad(raw)
		iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
		# iv = random.new().read(AES.block_size)
		key = self.key.get_key()
		cipher = AES.new(key, AES.MODE_CBC, iv)
		return base64.b64encode(iv + cipher.encrypt(raw))
		# after encoded, the content type is still 'str'
	
	def decrypt(self, enc):
		enc = base64.b64decode(enc)
		iv = enc[:16]
		key = self.key.get_key()
		cipher = AES.new(key, AES.MODE_CBC, iv)
		return unpad(cipher.decrypt(enc[16:]))

if __name__ == '__main__':
	# encodeTxt = base64.b64encode('jjsadifj')
	# print "@ type of encodeTxt is : %s" % type(encodeTxt)
	key = '123456789asdfghj'
	ciphertext = "This is a test!"
	aes = AESCipher()
	enctext = aes.encrypt(ciphertext)
	dectext = aes.decrypt(enctext)
	print "%s" % dectext
