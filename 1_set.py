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

# for i in range(255):                     # b
#     bit = chr(i).encode("utf-8")         # for printing: utf-8 encoding after \x7f continues with \xc2\x80
#     enc_string1 = unhexlify(enc_string)
#     dec_string = bytes([bit1^bit[-1] for bit1 in enc_string1]) # that's why we have to use [-1] to get the second byte
#     score = 100
#     for i in string.punctuation:
#         if i in str(dec_string):
#             score -= str(dec_string).count(i)
#     list_of_dec_strings.append((dec_string,score,bit.decode("utf-8")))
#
# list_of_dec_strings.sort(key=lambda y: y[1])
# print(list_of_dec_strings[-3:])

### easier:

for i in range(255):
    bit = i
    enc_string1 = unhexlify(enc_string)
    dec_string = bytes([bit1^bit for bit1 in enc_string1])
    score = 100
    for i in string.punctuation:
        if i in str(dec_string):
            score -= str(dec_string).count(i)
    list_of_dec_strings.append((dec_string,score,chr(bit)))

list_of_dec_strings.sort(key=lambda y: y[1])
print(list_of_dec_strings[-3:])


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
###

# Detect single-character XOR
#
# One of the 60-character strings in this file has been encrypted by single-character XOR.
#
# Find it.
#
# (Your code from #3 should help.)

#empty list for best strings
best_string = []

with open("4.txt", "r") as f:
    for count, line in enumerate(f):
        line = line.strip()
        line = line.split(" ")
        line = "".join(line)
        #print(line)

        list_of_dec_strings = []

        for i in range(255):
            bit = chr(i).encode("utf-8")  # see above
            enc_string1 = unhexlify(line)
            dec_string = bytes([bit1 ^ bit[-1] for bit1 in enc_string1])
            score = 100
            for i in string.punctuation:
                if i in str(dec_string):
                    score -= str(dec_string).count(i)
            list_of_dec_strings.append((dec_string, score, bit.decode("utf-8"), count))

        list_of_dec_strings.sort(key=lambda y: y[1])
        best_string.append(list_of_dec_strings[-1])

best_string.sort(key=lambda y: y[1])

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
