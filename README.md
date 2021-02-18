# bitflipper
Example of a bit-flipping attack against AES-256 CBC mode encryption. Change encrypted data without detection.

It is a common misconception that data encryption provides some sort of integrity protection.  In general, it does not.  The discussion below goes into it in some detail. The code in this repository illustrates a successful attack against AES-256 encryption in CBC mode, and also illustrates use of AES-256 with GCM, which **will** provide integrity, and defeat such attacks.


## Code
Written in Python 3. You'll need to install PyCryptoDome. It is a replacement for the old and flawed PyCrypto package.

[https://pypi.org/project/pycryptodome/] Their project page is [https://www.pycryptodome.org/]

If you have the old crypto installed, first uninstall it. CryptoDome is a drop-in replacement, also in the crypto namespace.

```
pip uninstall crypto
pip install cryptodome
```

The program ``bitflip.py`` demonstrates the successful attack.  The program ``authenc.py`` demonstrates a correct program and the failure of the same attack attempts.


## Discussion
TLDNR;
>Encryption provides _confidentiality_, but does not provide _integrity_. Some cipher modes are vulnerable to so-called “bit flipping attacks,” where encrypted data can be manipulated to read a certain way after decryption, without detection. Integrity is not a guarantee of encryption. For that, we need message authentication. Fortunately, you can get both, at once, and nearly automatically.

This distinction between confidentiality and integrity is extremely important to understand, so let’s explore that in some detail using an example.

Let’s say we have a web application. This application has two different classes of users – ordinary users, and administrative users.  Our application defines two roles – “ADMIN” and “USERS”. When an end user successfully authenticates, the application creates a web cookie called FIZBIN. This cookie contains various useful pieces of information related to the authenticated user. One of these pieces of information is the user’s Role, either “role=ADMIN” or “role=USERS”. When a request comes into the application, the application can either do a database lookup to check the role, or can check the cookie value. To improve performance, the application checks the cookie to determine whether the action requested is allowed for the role of the user.

The developer knows that an attacker could alter that value, and so she decides to encrypt the entire cookie value using 256-bit AES encryption in CBC mode. Good enough?  Unfortunately, no. Not even close.

The encryption means that the attacker cannot unscramble the cookie value.  It does **not** mean the attacker cannot successfully alter the Role value in the cookie so that it will decrypt to read “ADMIN” at the server side! In fact, it is often trivial to do so, even against 256-bit AES encryption.

_Confidentiality_ means that a value unknown to the attacker cannot be discovered. A value that _is_ known to the attacker does not have to be discovered – she already knows it. After all, the attacker logged in as an ordinary user. It isn’t hard to predict, then, that the Role in the cookie will read “USERS.” Here the developer has tried to use encryption to provide integrity, and it simply does not provide that.

_Integrity_ means that a message cannot be modified without detection. In this circumstance, it is important that the values in the cookie are not modified by an attacker. Encryption cannot provide that assurance.  Again, in many cases, it is possible to alter the encrypted cookie value so that when the server later decrypts it, the Role field will read “ADMIN” instead of “USERS.” And the server would never know.

Of course, as a professionally paranoid person, I encourage developers to encrypt cookies that contain sensitive data, but here it is critical that the data 
_integrity_ be protected.  Let’s see how to do both.

To ensure data integrity, you could try to use a hash. Just run the encrypted cookie through a hash algorithm and append the hash value to the cookie value. The server can recalculate the hash value and compare it to the value attached to the cookie. If either has been changed, the server knows something is wrong. Right?

Um, almost. The attacker will, of course, calculate the hash for the modified cookie and attach _that_ to the message. Now the check will pass, and the attacker becomes Admin again. So … what to do?  Maybe we encrypt the hash value?  Nope. Remember: encryption does not provide integrity. There’s a better way.

Instead, we use a _MAC_ (Message Authentication Code). A MAC provides both integrity and also authenticity. That is, we will know if the message is altered, and we will know if the message comes from the party we expect. In constructing this guarantee, we usually use a cryptographic hash, and so we call it an HMAC.  Here, we have a second key value that is secret. The key is mixed with the (encrypted) data in a particular way, and the hash is taken of both those together. Now an attacker cannot forge a new message, and also cannot modify the encrypted data without the server knowing that has happened.    Be careful, here.  Use the library code for doing an HMAC. Don’t roll your own – you’ll get it wrong and get burned.

The easy way (especially since we also want to encrypt that data), is to use a mode of encryption that provides data integrity _along with_ confidentiality. It does this by automatically creating an HMAC and including that with the encrypted data. It will also automatically verify the HMAC before making any attempt to decrypt the associated data. So, again, it’s not the encryption that provides the integrity, it is the HMAC. In this case, it’s just wrapped up conveniently in the crypto library to handle it all for you. (Yes, I know that’s an over-simplification, but it’s a working mental model, so go with it.)

This is important. A system that attempts to decrypt before validating the HMAC is likely flawed.  A system that calculates the HMAC and then encrypts the data and HMAC _together_ is possibly flawed.  A system that naively sticks a secret value in front of data then calculates the HMAC is flawed.  Use the libraries.  There are special cases for everything, but you don’t need to find them – use the libraries.

So, if the data you’re handling is not confidential, but needs integrity, use an HMAC. If it needs confidentiality, but alteration by an attacker will accomplish nothing, use encryption.  If you need both, (and you do more often than you might guess) use Authenticated Encryption.

As of January 2021, I suggest you use AES with mode GCM to get authenticated encryption with a minimum of fuss. As a bonus, GCM mode allows you to optionally add clear text data which will receive integrity protection but no encryption. Routing data or IP addresses, for example, might be a use for that.

**How does the attack work?**

To bit-flip any CBC-mode encrypted data, you need to know where the target bits appear in the encrypted data. You also need to know what they are when decrypted. This is easy if you can influence the generation of the encrypted message. You’ll need to calculate new values and place them one block earlier in the message than the bits you want to affect. When decrypted, the plaintext will have what you want rather than what was originally encrypted.
XOR the known plaintext bytes with your desired plaintext bytes to create a block of mask bits. Now XOR the mask bits with the encrypted bits at the corresponding offset of the previous block.

