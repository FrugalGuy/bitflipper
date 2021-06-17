import base64
from Crypto.Cipher import AES
from Crypto.Hash   import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
from codecs import encode

""" 
Encrypt an array of bytes using AES in Cipher Block Chaining mode
data: array of bytes to encrypt. This will pad if needed.
key: array of key bytes. Must be a legal AES key length.
Return an encrypted array of bytes.
Returned byte array layout: IV_bytes|cipher_bytes
"""
def encryptBytes(data,key):
    cipher = AES.new(key,AES.MODE_CBC)  # generate random IV
    if (isinstance(data,str)):          # convert string to bytes, if needed
        data = bytearray(data.encode())
    data = pad(data, 16)                # pad data to block length, if needed

    return cipher.iv + cipher.encrypt(data)  #return IV + ciphertext

"""
Return a Base64-encoded string of IV_bytes|cipher_bytes
"""
def encrypt(data,key):
    return base64.b64encode(encryptBytes(data,key)).decode("utf-8")

"""
Decrypt an array of bytes encrypted using AES in Cipher Block Chaining mode
data: array of bytes to decrypt. Must contain full blocks (16 bytes).
key: array of key bytes. Must be a legal AES key length, and match encrypting key.
Return a decrypted array of bytes. This will strip padding if there is any.
"""
def decryptBytes(data,key):
    # assumes IV is first block of input data, as was output by encryptBytes()
    iv = data[:16]
    content = data[16:]
    cipher = AES.new(key,AES.MODE_CBC,iv)
    result = cipher.decrypt(content)
    return unpad(result, 16)   # strip any padding from resulting plaintext

"""
Given a Base64-encoded string of IV_bytes|cipher_bytes, return array of decrypted bytes.
May be padded if plaintext bytes were padded.
"""
def decrypt(data,key):
    ptext = decryptBytes(base64.b64decode(data), key)
    if isinstance(ptext, str):  # not all data we encrypt is strings
        ptext = str(ptext)
    return ptext

"""
Given a byte array, return the SHA-512 hash (as a byte array)
Note that the SHA-512 is vulnerable to length extension attacks.
"""
def hashme(data):
    h = SHA512.new()
    h.update(data)
    return h.digest()

"""
Return a byte array of the bitwise Exclusive OR of input byte arrays
"""
def xor(a, b):
    return "".join([chr(ord(a[i]) ^ ord(b[i % len(b)])) for i in range(len(a))])

if __name__ == "__main__":

    print("A very simple data format: <role>  That's it. It either says USERS or ADMIN\n")
    ###
    ###  Server Side
    ###
    role = b'USERS'                             # 5 bytes of data
    
    print("Here is the payload: {0}".format(role), 
          "As bytes: {0}".format( encode(role,"hex") ), 
          "As bits:  " + "".join(format(ord(i), '08b') for i in 'USERS')) 

    secret_key = get_random_bytes(int(256/8))        # 256-bit key
    print("Random secret key: {0}".format( encode(secret_key, "hex") ), 
          "\nThe attacker won't need that. The server keeps it secret.\n")
    
    # Block cipher requires input data be a full block in length. Our routine will pad if needed.
    b = encryptBytes(role, secret_key)
    
    #print(" Roundtrip test of Base64: {}".format(decrypt( encrypt("HI MOM",secret_key), secret_key) ))
    print("The server sends out the encrypted cookie, which is two blocks long (32 bytes).",
          "\nThe first block of that is the random IV. It's needed for decryption, and is unique per message.",
          "\nThe remainder is the encrypted payload. It may be padded to end in a full block of bytes.")
    print("Encrypted Cookie Data Bytes: {0}".format( encode(b, "hex") ))   
    print("Composed of...    Random IV: {0}".format( encode(b[:16],"hex") ))
    print("And...                              Padded Ciphertext Bytes: {0}".format( encode(b[16:], "hex") ))
    print("For added 'security,' the app also sends a SHA-512 hash with the cookie.\n"
          "It will check the digest it receives back to 'ensure' the cookie was not modified. This doesn't work, of course.")
    h = hashme( b )
    print("digest: {}".format( encode(h, "hex")))

    print("\nNow, the server will decrypt with the secret key, just to show what was sent. Should be 'USERS'")
    
    ptext = decryptBytes(b,secret_key)
    
    print("Decrypted result is {0}".format(ptext))
    print("Okay, that worked. Now let's try an attack\n" if ptext == b'USERS' else "Something went wrong!\n")

    ###
    ### Client Side
    ###
    print("On the attacker's side ...\n",
          "\nWe flip some bits in the encrypted message, and see if the decrypted output can be changed successfully...",
          "\nWe XOR 'USERS' and 'ADMIN', then XOR that result with the first 5 bytes of the first block (the IV in this case)")
    
    flip = strxor(b'USERS', b'ADMIN')      # step 1. XOR known Plaintext with desired Plaintext
    xor_role_cipher = strxor(flip, b[:5])  # step 2. XOR that with same offset in _previous_ block
        
    fiddled = bytearray(xor_role_cipher + b[5:])  # in this case just fiddled with first 5 bytes of IV
    
    print("Modified crypto bytes is {0}".format( encode(fiddled, "hex") ),
          "\nNotice the changed bytes:  ^^^^^^^^^^   Notice that the rest of the message is unchanged.", 
          "\nSending modified cookie back to Server for decryption, along with our Admin request...")
    print("Oh. We also calculated a new digest for this modified cookie, so the server's check will succeed")
    h_2 = hashme(fiddled)
    print("modified digest: {}".format( encode(h_2, "hex")))
    
    ftext_output = decryptBytes(fiddled, secret_key)  # strips padding for us, if needed

    ###
    ### Server Side
    ###
    print("\nNow back at the server, check the hash, then if okay, do the decryption to read the Role...")
    print("Hash of received cookie matches received hash code (Duh!)" if hashme(fiddled) == h_2 else "Hash does not match!!")
    print("Decryption of modified message is {0}".format(ftext_output))
    print("It worked! Now the server treats you as an Administrator." if ftext_output == b'ADMIN' else "Something went wrong!")
