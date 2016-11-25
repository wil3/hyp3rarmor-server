__author__  = "Wil Koch"
__email__   = "wfkoch at gmail dot com"
__license__ = """ 
"""
import time, base64, binascii, json, socket
import random
from random import SystemRandom
import hashlib
import os
from struct import *
from captcha.image import ImageCaptcha
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac 
from hyp3rarmor.common.exceptions import Hyp3rArmorGenerationError 
from hyp3rarmor.common.constants import MAX_PORT_NUMBER


def dict_to_array(dict):
    arr = []
    for key, value in dict.iteritems():
        arr += value * [key]
    return arr

def valid_ip(ip):
    try: 
        socket.inet_aton(ip)
        return True
    except:
        return False

def valid_port(port):
    return port >= 0 and port <= MAX_PORT_NUMBER

def time_till_dealth(ttl):
    """For the current time, how much time is left for a tokens life

    Args:
        ttl: The time to live of the token

    Returns:
        Seconds left until dealth for the current token
    """
    return ttl - (time.time() % ttl)


def generate_universal_token(token_size):
    """Compute an universal AT, the AT can have duplicates and order does not matter

    Args:
        N: the size of the AT, i.e. the number of destination ports

    Returns:
        A dict of the destination ports and their count
    """
    token =  {}
    cryptogen = SystemRandom()
    for _ in xrange(token_size):
        dport = cryptogen.randrange(65534) + 1
        if dport not in token:
            token[dport] = 1
        else:
            token[dport] += 1
    return token

def token_to_json(token, expire, ttl):
    """Encode the token into format that can be sent to the client

    Args:
        token: the token, if defense is DN then it is encrypted, if it is still
        in its dict form it will be converted to an array
        expire: time in seconds the token will expire

    Returns:
        JSON string of the token and expiration
    """
    if isinstance(token, dict):
        token = dict_to_array(token)

    out = {}
    out["token"] = token
    out["expire"] = expire
    out["ttl"] = ttl

    return json.dumps(out)

def generate_random_word(word_len=6, seed=None):
    """Generate a random word

    Args:
        word_len: Length of the random word to be generated

    Returns:
        The random word
    """
    ALLOWEDCHARS = "abcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWZYZ0123456789"
    word = ""
    r = SystemRandom()
    if seed:
	random.seed(seed)
	r = random

    for _ in xrange(word_len):
        i = r.randrange(len(ALLOWEDCHARS))
        word = word + ALLOWEDCHARS[i]
    return word


def derive_key(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
    )
    #key = base64.b64encode(kdf.derive(password))
    key = kdf.derive(password)
    return (key, salt)

def token_to_string(token):
    return ",".join(map(str,token))

def string_to_token(string):
    return map(int, string.split(","))

def protect_token(token, seed=None, file=None):
    """If using defense for DN-bots this will encrypt the token
    and create a challenge

    Args:
        token: the token to protect

    Returns:
        a protected token
    """
    #TODO This captcha is trivial to break
    answer = generate_random_word(6, seed=seed) 
    #Key stretch
    plaintext = token_to_string(token)

    #key = answer # base64.b64encode(hashlib.sha256(answer).digest())
    #crypt = Fernet(key)
    # Modifying token is outside threat model, this should be protected in any
    # case by TLS. Each key is only usd to encrypt a single message (one-time)
    # therefore we neglect the IV
    # Generate a random 96-bit IV.
    #
    (key, salt) = derive_key(answer)


    iv = os.urandom(12)
    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()


    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (answer, salt, iv, ciphertext, encryptor.tag)


def generate_challange(answer, file=None):
    image = ImageCaptcha()
    if file:
        image.write(answer, file)
        return file 
    else:
        image_data = image.generate(answer)
        return image_data


def generate_seed(file_path):
    """Generate a seed and save to the file system

    Args:
        file_path: location to save seed

    Returns:
        The random seed
    """
    #Generate 256 bits random
    random_hex = binascii.b2a_hex(os.urandom(32)) 
    with open(file_path, "w") as f:
        f.write(random_hex)
    return random_hex

def load_seed(file_path):
    """Load the seed from the given file

    Returns
        The seed read from the file
    """
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return f.read()
    else:
        return generate_seed(file_path)


def generate_ip_bound_token(token_size, ip, totp, otp_time=None):
    """
    IP bound ATs are generated and distributed on a dedicated server, because 
    the stealth server does not communicate with the other server TOTP must be used. 
    The seed to the TOTP must be kept secret

    l length of key in bytes default 32 bytes or 256 bits

    Args:
        token_size: the size of the AT, i.e. the number of destination ports
        ip: the IP address to bind the token to 
        totp: A time based one-time password object to compute the AT from
        otp_time: (optional) The time to compute the token for, otherwise the current time is used

    Returns:
        A tuple consiting of the dict AT and the time for which it was generated

    Raises:
        Hyp3rArmorGenerationError: The time based one-time passsword class
        was not initiated.
    """
    if not totp:
        raise Hyp3rArmorGenerationError("TOTP not initiated")

    token = {}
    if not otp_time:
        otp_time = time.time()
    totp_value = totp.generate(otp_time)
    for c in xrange(token_size):
        msg = "{}:{}".format(ip, c)
        h = hmac.HMAC(totp_value, hashes.SHA256(), backend=default_backend())
        h.update(msg)
        b = unpack('>i', h.finalize()[:4])[0]
        dport = b & 0xFFFF
        if dport not in token:
            token[dport] = 1
        else:
            token[dport] += 1

    return (token, otp_time)

