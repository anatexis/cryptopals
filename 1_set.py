# challenge 1

from base64 import b64encode, b64decode

def hex_to_base64(hex_string):
    """
    Convert a hex string to base64
    source: https://stackoverflow.com/a/63595341
    """
    b64 = b64encode(bytes.fromhex(hex_string)).decode()
    return b64


hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")

## %

# challenge 2


# Fixed XOR
#
# Write a function that takes two equal-length buffers and produces their XOR combination.
#
# If your function works properly, then when you feed it the string:
#
# 1c0111001f010100061a024b53535009181c
#
# ... after hex decoding, and when XOR'd against:
#
# 686974207468652062756c6c277320657965
#
# ... should produce:
#
# 746865206b696420646f6e277420706c6179

from binascii import hexlify, unhexlify

string1 = "1c0111001f010100061a024b53535009181c"
string2 = "686974207468652062756c6c277320657965"

string11 = unhexlify(string1)
string22 = unhexlify(string2)

def xor_func(string1, string2):
    xor = bytes([bit1^bit2 for (bit1,bit2) in zip(string1,string2)]) #bytes([int, int, int]) returns
    return xor


xor_func(string11,string22)



#Challenge 3

# Single-byte XOR cipher
#
# The hex encoded string:
#
# 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
#
# ... has been XOR'd against a single character. Find the key, decrypt the message.
#
# You can do this by hand. But don't: write code to do it for you.
#
# How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
# Achievement Unlocked
#
# You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.



enc_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
import string



list_of_dec_strings = []

for i in range(255):
    bit = i
    enc_string1 = unhexlify(enc_string)
    dec_string = bytes([bit1^bit for bit1 in enc_string1])
    characters = string.ascii_letters + " "
    score = round(sum([chr(x) in characters for x in dec_string])/len(dec_string),2) #just works for english [a-zA-Z]
    list_of_dec_strings.append((dec_string,score,chr(bit)))

result = list(filter(lambda x: (x[1]>0.9), list_of_dec_strings))
print(result)


#%%
# source: https://cedricvanrompay.gitlab.io/cryptopals/challenges/01-to-08.html
# def attack_single_byte_xor(ciphertext):
#     best = {"nb_letters": 0}
#     for i in range(2 ** 8):
#         candidate_key = i.to_bytes(1, byteorder='big')
#         candidate_message = bxor(ciphertext, candidate_key * len(ciphertext))
#         nb_letters = sum([x in ascii_text_chars for x in candidate_message])
#         if nb_letters > best['nb_letters']:
#             best = {"message": candidate_message, 'nb_letters': nb_letters, 'key': candidate_key}
#
#     if best['nb_letters'] > 0.7 * len(ciphertext):
#         return best
#     else:
#         raise InvalidMessageException('best candidate message is: %s' % best['message'])

#%%

### Challenge 4

# Detect single-character XOR
#
# One of the 60-character strings in this file has been encrypted by single-character XOR.
#
# Find it.
#
# (Your code from #3 should help.)


def detect_singel_char_xor(inputstring,cutoffvalue):
    list_of_dec_strings = []

    for i in range(255):
        bit = i
        enc_string1 = unhexlify(inputstring) #input string has to be hex
        dec_string = bytes([bit1 ^ bit for bit1 in enc_string1])
        characters = string.ascii_letters + " " #get ascii letters + space
        score = round(sum([chr(x) in characters for x in dec_string]) / len(dec_string),2)  # just English [a-zA-Z]
        list_of_dec_strings.append((dec_string, score, chr(bit)))

    result = list(filter(lambda x: (x[1] > cutoffvalue), list_of_dec_strings)) # filter for score > cutoffvalue

    return result



with open("4.txt", "r") as f:

        list_of_lines = []
        for count,line in enumerate(f):
            line = line.strip()
            result = detect_singel_char_xor(line,0.8)
            if result != []:
                result.sort(key = lambda x: x[1]) #sort the for the best result per line
                list_of_lines.append((result[0],count)) # only get the best result per line


print(list_of_lines)

#%%

# Implement repeating-key XOR
#
# Here is the opening stanza of an important work of the English language:
#
# Burning 'em, if you ain't quick and nimble
# I go crazy when I hear a cymbal
#
# Encrypt it, under the key "ICE", using repeating-key XOR.
#
# In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd
# against I, the next C, the next E, then I again for the 4th byte, and so on.
#
# It should come out to:
#
# 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
# a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
#
# Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file.
# Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.

string_to_enc = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = "ICE"
string_bytes = bytes(string_to_enc,"utf-8") # convert string to bytes
key_bytes = bytes(key,"utf-8")

# get a byte stream(?) of the same length of each i_bytes
key_bytes_stream = key_bytes * ((len(string_bytes)//len(key)) + 1) # key_bytes[:(len(string_bytes)%len(key))]

enc = hexlify(bytes([bit1^bit2 for (bit1,bit2) in zip(string_bytes, key_bytes_stream)]))

print(enc)

def repeating_key_xor(string_to_enc, key):
    string_bytes = bytes(string_to_enc, "utf-8")  # convert string to bytes
    key_bytes = bytes(key, "utf-8")

    key_bytes_stream = key_bytes * ((len(string_bytes) // len(key)) + 1)

    return hexlify(bytes([bit1^bit2 for (bit1,bit2) in zip(string_bytes, key_bytes_stream)]))

# and to decode:


def decr_reapeating_key_xor(enc_string, key):
    string_bytes = enc_string
    key_bytes = bytes(key, "utf-8")
    key_bytes_stream = key_bytes * ((len(string_bytes) // len(key)) + 1)

    return bytes([bit1 ^ bit2 for (bit1, bit2) in zip(unhexlify(string_bytes), key_bytes_stream)])


enc_str = repeating_key_xor("Ich liebe dich!", "ICE")

decr_reapeating_key_xor(enc_string, "ICE")

#%%





string1 = "this is a test"
string2 = "wokka wokka!!!"
string1 = bytes(string1,"utf-8")
string2 = bytes(string2, "utf-8")


def hamming_distance(a, b):
    return sum(bin(byte).count('1') for byte in xor_func(a,b))

print(hamming_distance(string1,string2))
