# Author : Muhammad Faizan Ul Ghani

from Crypto.Cipher import AES
from random import randint
import urllib

# Helper Func's from other sets.

def xorBlocks(str1, str2):
	return ''.join(chr(ord(str1[i]) ^ ord(str2[i])) for i in range(0,len(str1))) 

def has_repeated_block(str1):
	block_size = 16
	str_blocks = [str1[i * block_size:block_size * (i+1)] for i in range(0, len(str1)/block_size)]
	if len(str_blocks) == len(set(str_blocks)):
		return False
	return True

# Challenge 1
def pkcsEncode(str1, block_size):

	pad_len = 0
	toPad = len(str1) % block_size
	if toPad:
		pad_len = block_size - toPad 

	return str1 + ('%02d' % pad_len).decode('hex') * pad_len

# Challenge 2

def pkcsDecode(str1):
	pad_len = ord(str1[-1])
	return str1[:-pad_len]

def decryptAESinCBC(cipherText, key, iv):
	obj = AES.new(key, AES.MODE_ECB)

	block_size = 16
	blocks = [cipherText[i * block_size:block_size * (i+1)] for i in range(0, len(cipherText)/block_size)]
	d_str = ''
	p_block = iv

	for cur_block in blocks:
		d_block = obj.decrypt(cur_block)
		d_str += xorBlocks(d_block, p_block)
		p_block = cur_block
	return pkcsDecode(d_str)

# Challenge 3
def encryptAESinCBC(text, key, iv):
	obj = AES.new(key, AES.MODE_ECB)
	
	block_size = 16
	text = pkcsEncode(text, block_size)

	blocks = [text[i * block_size:block_size * (i+1)] for i in range(0, len(text)/block_size)]
	e_str = ''
	p_block = iv

	for cur_block in blocks:
		x_block = xorBlocks(cur_block, p_block)
		e_str += obj.encrypt(x_block)
		p_block = cur_block
	return e_str

def generateBlock(block_size):
	return ''.join([chr(randint(0,255)) for i in range(0,block_size)])

def encrption_oracle(text):
	block_size = 16
	toCBC = randint(0,1)
	key = generateBlock(block_size)
	iv = generateBlock(block_size)
	beforeRand = randint(5,10)
	afterRand = randint(5,10)
	text = generateBlock(beforeRand) + text + generateBlock(afterRand)

	if toCBC:
		return encryptAESinCBC(text, key, iv)
	else:
		obj = AES.new(key, AES.MODE_ECB)
		text = pkcsEncode(text, block_size)
		return obj.encrypt(text)


# Challenge 4
key4 = generateBlock(16)
toAppend = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

def encryptAESinECB(text):
	global key4, toAppend
	obj = AES.new(key4, AES.MODE_ECB)
	text = text + toAppend.decode('base64')
	return obj.encrypt(pkcsEncode(text, 16))

def getBlockSize():
	e_str_l = len(encryptAESinECB(""))
	i = 1
	t_byte = 'A'
	while True:
		t_str = t_byte*i
		t_e_str = encryptAESinECB(t_str)
		if len(t_e_str) != e_str_l:
			return len(t_e_str) - e_str_l
		i += 1

def detectECB():
	block_size = getBlockSize()
	t = generateBlock(block_size)
	e_str = encryptAESinECB(t)
	if e_str[0:block_size] == e_str[block_size:block_size*2]:
		return True
	return False

def decryptAESinECBsimple():
	block_size = getBlockSize()
	e_str = encryptAESinECB("")
	n_blocks = len(e_str)/block_size

	charset = ''.join(chr(i) for i in range(0,255))

	d_str = ''
	block_dict = {}

	while True:
		i_len = (block_size - (len(d_str)%block_size)-1)
		i_block = 'A'*i_len
		i_e_block = encryptAESinECB(i_block)

		block_len = len(i_block)+len(d_str)+1
		for c in charset:
			t_str = encryptAESinECB(i_block + d_str + c)
			
			block_dict[t_str[:block_len]] = c

		temp = i_e_block[:block_len]
		if temp in block_dict:
			d_str += block_dict[temp]
		else:
			break;
	return d_str

# Challenge 5
uid = 10
key5 = generateBlock(16)

def profile_for(email):
	global uid
	email = email.replace('&', '').replace('=','')
	fields = ['email', 'uid', 'role']
	profile = {'email':email, 'uid':uid, 'role':'user'}
	return "&".join('%s=%s' % (i, profile[i]) for i in fields)

def encryptProfile(profile):
	global key5
	obj = AES.new(key5, AES.MODE_ECB)
	return obj.encrypt(pkcsEncode(profile, 16))

def decryptProfile(profile):
	global key5
	obj = AES.new(key5, AES.MODE_ECB)
	d_profile = pkcsDecode(obj.decrypt(profile))
	print d_profile
	return dict(urllib.splitvalue(i) for i in d_profile.split('&') if len(i.split('=')) == 2)  

def adminProfile():
	email1 = 'GGGGGGGGGGadmin'
	e_str1 = encryptProfile(profile_for(email1))
	email2 = 'ghani@sol.com'
	e_str2 = encryptProfile(profile_for(email2))

	fake_admin = e_str2[0:32] + e_str1[16:32] + e_str2[32:]
	return decryptProfile(fake_admin)

# Challenge 6
key6 = generateBlock(16)
prefix6 = generateBlock(randint(0,50))

def encryptAESinECB6(text):
	global key6, prefix6, toAppend
	obj = AES.new(key6, AES.MODE_ECB)
	text = prefix6 + text + toAppend.decode('base64')
	return obj.encrypt(pkcsEncode(text, 16))

def getBlockSize6():
	e_str_l = len(encryptAESinECB6(""))
	i = 1
	t_byte = 'A'
	while True:
		t_str = t_byte*i
		t_e_str = encryptAESinECB6(t_str)
		if len(t_e_str) != e_str_l:
			return len(t_e_str) - e_str_l
		i += 1

def detectECB6():
	block_size = getBlockSize6()
	t = generateBlock(block_size)
	e_str = encryptAESinECB6(t)
	if e_str[block_size:block_size*2] == e_str[block_size*2:block_size*3]:
		return True
	return False

def getPrefixLength():
	global toAppend
	block_size = getBlockSize6()
	toAppend_len = len(toAppend.decode('base64'))
	e_str_l = len(encryptAESinECB6("")) - toAppend_len
	t_e_l = e_str_l
	t_byte = 'A'
	while t_e_l == e_str_l:
		t_byte += 'A'
		e_str_l = len(encryptAESinECB6(t_byte))
	return e_str_l - len(t_byte) - toAppend_len - (block_size+2)

def crackECB():
	block_size = getBlockSize6()
	e_str = encryptAESinECB6("")
	n_blocks = len(e_str)/block_size

	charset = ''.join(chr(i) for i in range(0,255))

	d_str = ''
	block_dict = {}

	while True:
		i_len = (block_size - (len(d_str)%block_size)-1)
		i_block = 'A'*i_len
		i_e_block = encryptAESinECB6(i_block)

		block_len = len(i_block)+len(d_str)+1
		for c in charset:
			t_str = encryptAESinECB6(i_block + d_str + c)
			
			block_dict[t_str[:block_len]] = c

		temp = i_e_block[:block_len]
		if temp in block_dict:
			d_str += block_dict[temp]
		else:
			break;
	return d_str
	
# Challenge 7
def paddingValidation(str1):
	try:
		l = len(str1)
		pad_len = ord(str1[-1])
		if str1[-pad_len:] != chr(pad_len)*pad_len:
			raise
		if ord(str1[l-pad_len-1]) == pad_len:
			raise
		print "Valid Padding : " + str1[:-pad_len]
	except:
		print "Invalid Padding"

# Challenge 8
key8 = generateBlock(16)
iv8 = generateBlock(16)

def encrption_oracle8(text):
	global key8, iv8
	text = text.replace('=','%3d').replace(';', '%3b')
	prefix = "comment1=cooking%20MCs;userdata="
	suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
	text = prefix + text + suffix
	return encryptAESinCBC(text, key8, iv8)

def decryption_oracle8(ciphertext):
	global key8, iv8
	d_str = decryptAESinCBC(ciphertext, key8, iv8)
	print d_str
	return d_str.count(';admin=true;') > 0

def getBlockSize8():
	e_str_l = len(encrption_oracle8(""))
	i = 1
	t_byte = 'A'
	while True:
		t_str = t_byte*i
		t_e_str = encrption_oracle8(t_str)
		if len(t_e_str) != e_str_l:
			return len(t_e_str) - e_str_l
		i += 1


# # Challenge 1 Test
# print 'YELLOW SUBMARINE\x04\x04\x04\x04' == pkcsEncode('YELLOW SUBMARINE', 20)

# # Challenge 2 Test
# data2 = ''
# with open("2.txt") as f:
# 	data2 = f.read().replace('\n', '').decode('base64')
# print decryptAESinCBC(data2, 'YELLOW SUBMARINE', '\x00'*16)

# # Challenge 3 Test
# e_str = encrption_oracle("A"*3*16)
# if has_repeated_block(e_str):
# 	print "ECB"
# else:
# 	print "CBC"

# # Challenge 4 Test
# print decryptAESinECBsimple()

# # Challenge 5 Test
# print adminProfile()

# Challenge 6 Test

# # Challenge 7 Test
# paddingValidation("ICE ICE BABY\x01\x02\x03\x04")

# Challenge 8 Test

