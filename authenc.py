from base64 import b64encode, b64decode
import json  # dumps, loads  I prefer writing 'json.dumps' in the code for clarity.
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
from codecs import encode

"""
Encrypt an array of bytes using AES in GCM mode (gives authentication, too)
data: array of bytes to encrypt. This mode does not require padding.
key: array of key bytes. Must be a legal AES key length.
a_data: array of bytes to be authenticated, but not encrypted. Default is None.

Returns a dictionary {'nonce':random_nonce_bytes,        'additional':a_data, 
                      'ciphertext':encrypted_data_bytes, 'tag':tag_bytes}
NOTE: a_data in the returned dictionary will be a byte array, even if input was not
"""
def encryptBytes(data,key,a_data=None):
    cipher = AES.new(key,AES.MODE_GCM)  # generate random nonce
    if (a_data):
        if (isinstance(a_data,str)):
            a_data = bytearray(a_data.encode())
        cipher.update(a_data)           # authenticate optional a_data
    if (isinstance(data,str)):          # convert string to bytes, if needed
        data = bytearray(data.encode())
    ctext, tag = cipher.encrypt_and_digest(data)  # enc and authenticate data
    
    keys = [ 'nonce',      'additional', 'ciphertext', 'tag' ]
    vals = [  cipher.nonce, a_data,       ctext,        tag   ]
    result = dict(zip(keys, vals))

    #print("Debug: encrypt result is", result)
    return result  # return dictionary of return values

"""
Return a Base64-encoded string of IV_bytes|cipher_bytes
"""
def encrypt(data,key,a_data=None):
    d = encryptBytes(data, key, a_data) # get dictionary of values
    i = dict()
    for k, v in d.items():
        if v:   # skip keys without a value (eg 'additional'=None)
            i[k] = b64encode(v).decode("utf-8")
    return json.dumps(i)    


"""
Decrypt an array of bytes encrypted using AES in GCM mode. Checks auth first!
data: array of bytes to decrypt.
key: array of key bytes. Must be a legal AES key length, and match encrypting key.
tag: array of authentication tag bytes. Must match the tag gen'd at encryption time.
nonce: array of nonce bytes. Must match the nonce generated at encryption time.
a_data: optional array of extra data bytes. These are authenticated, not encrypted.
Return a decrypted array of bytes. Returns None if anything has been modified.
"""
def decryptBytes(in_dict,key):
    result = None

    try:
        cipher = AES.new(key,AES.MODE_GCM,nonce=in_dict['nonce'])
        #print("Debug: nonce {}".format(encode(in_dict['nonce'], "hex")))
        if ('additional' in in_dict.keys() and in_dict['additional'] != None):
            a_data = in_dict['additional']
            if (isinstance(a_data,str)):
                a_data = bytearray(a_data.encode())
            cipher.update(a_data)           # authenticate optional a_data

        result = cipher.decrypt_and_verify(in_dict['ciphertext'], in_dict['tag'])
    except ValueError as err:
        print("Error during decryption: {}".format(err))
        result = None
    return result

"""
Given a JSON string of Base64-encoded values, return array of decrypted bytes.
Input is the output of encrypt(data,key,a_data=None) function.
"""
def decrypt(data,key):
    js = json.loads(data)
    jv = { k:b64decode(js[k]) for k in js.keys() }

    return decryptBytes(jv, key)

"""
Return a byte array of the bitwise Exclusive OR of input byte arrays
"""
def xor(a, b):
    return "".join([chr(ord(a[i]) ^ ord(b[i % len(b)])) for i in range(len(a))])

if __name__ == "__main__":
    print("A very simple data format: <role>  That's it. It either says USERS or ADMIN\n")
    
    role = b'USERS'                             # 5 bytes of data
    
    print("Here is the payload: {0}".format(role), 
          "As bytes: {0}".format( encode(role,"hex") ), 
          "As bits: '" + "".join(format(ord(i), '08b') for i in 'USERS') + "'") 

    secret_key = get_random_bytes(int(256/8))        # 256-bit key
    print("Random secret key: {0}".format( encode(secret_key, "hex") ), "\n"
          "The attacker won't need that. The server keeps it secret.\n")
    
    ## Quick test of base64 string encrypt / decrypt loop
    #print(" Base64 round-trip returns {}".format( 
    #      decrypt( encrypt(role, secret_key, a_data="Hi Mom"), secret_key)))
    #b64_json = encrypt(role, secret_key, a_data="Hi Mom")
    #print("*** From Decrypt: {}".format(decrypt(b64_json, secret_key)))
    
    ##
    ## My Python function returns a Python dictionary object, which contains
    ## the nonce, the encrypted bytes, any additional authenticated data, and
    ## the authentication tag. We need to send all that to the other party
    ## so that they can authenticate and decrypt the data. Assumes they have 
    ## the key (or in this example, we retain the key. The other party is not
    ## supposed to read or modify the encrypted cookie at all).
    ##
    b = encryptBytes(role, secret_key)  # no additional data

    print("The server sends out the encrypted cookie.\n"
          "The nonce is random. It's needed for decryption, and unique per message.\n"
          "The tag provides authentication and integrity protection.")
    print("Encrypted data bytes: \nrole={0}&nonce={1}&tag={2}".format( 
          encode(b['ciphertext'], "hex"), 
          encode(b['nonce'], "hex"), 
          encode(b['tag'], "hex") ))
    jsn = encrypt(role, secret_key)
    print("Or, as a JSON-formatted Base64-encoded string: \n{}".format(jsn))

    print("\nNow, the server will decrypt with the secret key, just to show what was sent. "
          "Should be 'USERS'")
    
    decrypt(jsn, secret_key)            # just here to exercise the Base64 function
    ptext = decryptBytes(b,secret_key)
    
    print("Decrypted result is {0}".format(ptext))
    print("Okay, that worked. Now let's try an attack\n" if ptext == b'USERS' else "Something went wrong!\n")

    print("On the attacker's side ...\n\n"
          "You can't flip bits with this mode of encryption. Normally changes to the encrypted data "
          "are not detectable (except the result is garbage) as long as the length of the data does "
          "not change. With this authenticated encryption, though, we cannot change *anything* or "
          "the system will immediately alert the program that the data has been modified.\n"
          "We XOR 'USERS' and 'ADMIN', then XOR that result with the 5 bytes of the encrypted data...")
    
    flip = strxor(b'USERS', b'ADMIN')      # step 1. XOR known Plaintext with desired Plaintext
    xor_role_cipher = strxor(flip, b['ciphertext'])  # step 2. XOR that with ciphertext
        
    b['ciphertext'] = bytearray(xor_role_cipher)
    
    print("Modified crypto bytes is {0}".format( encode(b['ciphertext'], "hex") ),
          "\nNotice the changed bytes:  ^^^^^^^^^^", 
          "\nSending modified cookie back to Server for decryption, along with our Admin request...\n")
    
    ftext_output = decryptBytes(b, secret_key)
    
    print("Decryption of modified message is {0}".format(ftext_output))
    print("Attack FOILED! We detected that the data was modified. Attacker is kicked off." if ftext_output == None else "Something went wrong!")