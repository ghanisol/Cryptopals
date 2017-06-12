# Author : Muhammad Faizan Ul Ghani

from Crypto.Cipher import AES

# Challenge 1
def hexToBase64 (str1):
	return str1.decode('hex').encode('base64')

# Challenge 2
def fixedXOR(str1, str2):
	return "%x" % (int(str1, 16) ^ int(str2, 16))

# Challenge 3
def textScore(str1):
	freq = {'a':834, 'b':154, 'c':273, 'd':414, 'e':1260, 'f':203,
			'g':192, 'h':611, 'i':671, 'j':23, 'k':87, 'l':424,
			'm':253, 'n':680, 'o':770, 'p':166, 'q':9, 'r':568,
			's':611, 't':937, 'u':285, 'v':106, 'w':234, 'x':20,
			'y':204, 'z':6, ' ':2320}
	
	score = 0
	for i in str1.lower():
		if i in freq:
			score += freq[i]

	return score

def singleByteXORdecode(str1):
	max_score = 0
	max_score_key = 0
	max_score_str = ""

	for i in range(0,255):
		d_str = ''.join([chr(ord(x) ^ i ) for x in str1.decode('hex')])
		
		score = textScore(d_str)
		if (score > max_score):
			max_score = score
			max_score_str = d_str
			max_score_key = i
	return max_score, max_score_key, max_score_str

# Challenge 4
def detectSingleCharXOR(filename):
	max_score = 0
	max_score_str = ""

	with open(filename, 'r') as f:
		e_str = f.readline()
		while e_str != '':
			str_score, d_key, d_str = singleByteXORdecode(e_str.strip())
			if (str_score > max_score):
				max_score = str_score
				max_score_str = d_str
			e_str = f.readline()
	return max_score_str

# Challenge 5
def repeatingKeyXOR(str1, key):

	d_str = ''
	k = 0
	for i in str1:
		d_str += chr(ord(i) ^ ord(key[k]))
		k = (k+1)%len(key)

	return d_str.encode('hex')

# Challenge 6
def hammingDist(str1, str2):
	dist = 0
	str1 = ''.join(format(ord(i), '08b') for i in str1)
	str2 = ''.join(format(ord(i), '08b') for i in str2)
	for (i,j) in zip(str1, str2):
		dist += ord(i) ^ ord(j)
	return dist

def guessKeySize(str1):
	key_sizes = []

	for size in range(2,40):
		dist = hammingDist(str1[:size], str1[size:size*2])
		key_sizes.append((dist/size, size))
	
	return sorted(key_sizes)[:-3]
		
def guessKey(str1, key_size):
	str_blocks = [str1[i * key_size:key_size * (i+1)] for i in range(0, len(str1)/key_size)]
	
	key = []
	str_blocks = map(list, zip(*str_blocks))

	for block in str_blocks:
		_, keychar, _ = singleByteXORdecode(''.join(block).encode('hex'))
		key.append(chr(keychar))

	return ''.join(key)

def breakRepeatingKeyXOR(filename):
	cipherText = ''
	with open(filename, 'r') as f:
		cipherText = f.read().replace('\n', '').decode('base64')

	key_sizes = guessKeySize(cipherText)
	max_score = 0
	max_score_str = ''

	for _, key_size in key_sizes:
		key = guessKey(cipherText, key_size)

		d_str = repeatingKeyXOR(cipherText, key).decode('hex')
		str_score = textScore(d_str)
		if str_score > max_score:
			max_score = str_score
			max_score_str = d_str

	return max_score_str

# Challenge 7
def decryptAESinECB(filename, key):
	obj = AES.new(key, AES.MODE_ECB)
	cipherText = ''
	with open (filename, 'r') as f:
		cipherText = f.read().replace('\n', '').decode('base64')

	return obj.decrypt(cipherText)

# Challenge 8
def has_repeated_block(str1):
	block_size = 16
	str_blocks = [str1[i * block_size:block_size * (i+1)] for i in range(0, len(str1)/block_size)]
	if len(str_blocks) == len(set(str_blocks)):
		return False
	return True

def detectAESinECB(filename):
	e_strs = []
	with open(filename, 'r') as f:
		data = f.readlines()
	for line in data:
		if has_repeated_block(line.strip()):
			e_strs.append(line)

	return e_strs


# # Challenge 1 Test
# print hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")


# # Challenge 2 Test
# print fixedXOR("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")

# # Challenge 3 Test
# score, key, d_str = singleByteXORdecode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
# print d_str, key, score

# # Challenge 4 Test
# print detectSingleCharXOR("4.txt")

# # Challenge 5 Test
# print repeatingKeyXOR("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE")

# # Challenge 6 Test
# print breakRepeatingKeyXOR("6.txt")

# # Challenge 7 Test
# print decryptAESinECB("7.txt", 'YELLOW SUBMARINE')

# # Challenge 8 Test
# print detectAESinECB("8.txt")

