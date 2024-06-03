from subprocess import check_output as run
from base64 import b64decode

ascii_text_chars = list(range(97, 122)) + [32]

def bxor(a, b):
    "bitwise XOR of bytestrings"
    return bytes([ x^y for (x,y) in zip(a, b)])

# the bitwise-xor of two strings will have ones
# only in places where the two strings have different bits
# hence, computing the hamming distance of the two strings
# is equivalent to counting the numbers of one (the "hamming weight") of their XOR sum
def hamming_distance(a, b):
    return sum(bin(byte).count('1') for byte in bxor(a,b))

def remote():
  """Retrieve ciphertext from the Cryptopals site."""
  url = "https://cryptopals.com/static/challenge-data/6.txt"
  return run(['curl', '--silent', url]).decode('ascii')

ciphertext = b64decode(remote())

with open("././challenge6.txt") as file:
        ciphertext = b64decode(file.read())

def score_vigenere_key_size(candidate_key_size, ciphertext):
    # as suggested in the instructions,
    # we take samples bigger than just one time the candidate key size
    slice_size = 2*candidate_key_size

    # the number of samples we can make
    # given the ciphertext length
    nb_measurements = len(ciphertext) // slice_size - 1

    # the "score" will represent how likely it is
    # that the current candidate key size is the good one
    # (the lower the score the *more* likely)
    score = 0
    for i in range(nb_measurements):

        s = slice_size
        k = candidate_key_size
        # in python, "slices" objects are what you put in square brackets
        # to access elements in lists and other iterable objects.
        # see https://docs.python.org/3/library/functions.html#slice
        # here we build the slices separately
        # just to have a cleaner, easier to read code
        slice_1 = slice(i*s, i*s + k)
        slice_2 = slice(i*s + k, i*s + 2*k)

        score += hamming_distance(ciphertext[slice_1], ciphertext[slice_2])

    # normalization: do not forget this
    # or there will be a strong biais towards long key sizes
    # and your code will not detect key size properly
    score /= candidate_key_size
    
    # some more normalization,
    # to make sure each candidate is evaluated in the same way
    score /= nb_measurements

    return score

def find_vigenere_key_length(ciphertext, min_length=2, max_length=30):
    # maybe this code is a bit over-sophisticated
    # it just outputs the key size for wich
    # the score at the "score_vigenere_key_size" function is the *lowest*
    key = lambda x: score_vigenere_key_size(x,ciphertext)
    return min(range(min_length, max_length), key=key)

def attack_single_byte_xor(ciphertext):
    # a variable to keep track of the best candidate so far
    best = None
    for i in range(2**8): # for every possible key
        # converting the key from a number to a byte
        candidate_key = i.to_bytes(1, byteorder='big')
        keystream = candidate_key*len(ciphertext)
        candidate_message = bxor(ciphertext, keystream)
        nb_letters = sum([ x in ascii_text_chars for x in candidate_message])
        # if the obtained message has more letters than any other candidate before
        if best == None or nb_letters > best['nb_letters']:
            # store the current key and message as our best candidate so far
            best = {"message": candidate_message, 'nb_letters': nb_letters, 'key': candidate_key}
    return best

def attack_repeating_key_xor(ciphertext):
    keysize = find_vigenere_key_length(ciphertext)

    # we break encryption for each character of the key
    key = bytes()
    message_parts = list()
    for i in range(keysize):
        # the "i::keysize" slice accesses elements in an array
        # starting at index 'i' and using a step of 'keysize'
        # this gives us a block of "single-character XOR" (see figure above)
        part = attack_single_byte_xor(bytes(ciphertext[i::keysize]))
        key += part["key"]
        message_parts.append(part["message"])

    # then we rebuild the original message
    # by putting bytes back in the proper order
    # TODO again code may be over-sophisticated and not very readable here
    message = bytes()
    for i in range(max(map(len, message_parts))):
        message += bytes([part[i] for part in message_parts if len(part)>=i+1])

    return {'message':message, 'key':key}

result = attack_repeating_key_xor(ciphertext)
print("key:",result["key"],'\n')
print(len(str(result['key'])))
print('message:\n')
print(result["message"].decode())