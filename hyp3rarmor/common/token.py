import time
import jsonpickle
from random import SystemRandom
from hyp3rarmor.common.exceptions import  * 
from hyp3rarmor.common.constants import MAX_PORT_NUMBER

class Token(object):
    
    def __init__(self,  ttl, length=None, dports=None):
        self.ttl = ttl 
        self.dports = dports 

    def to_json(self):
        return jsonpickle.encode(self, unpicklable=False)

    def _dict_to_array(self, dict):
        arr = []
        for key, value in dict.iteritems():
            arr += value * [key]
        return arr

    def time_till_dealth(self, ttl, alt_time=None):
        """For the current time, how much time is left for a tokens life

        Args:
            ttl: The time to live of the token

        Returns:
            Seconds left until dealth for the current token
        """
        return ttl - ((alt_time or time.time()) % ttl)


class UniversalToken(Token):
    def __init__(self, ttl, length=None, dports=None):
        if not length and not dports:
            raise Hyp3rArmorTokenError("Must specify length to generate new token or initialize token with destination ports")

        if not dports:
            dports = self._dict_to_array(self._generate_dports(length))

        # FIXME this should be based on the clock
        self.expire = time.time() +  self.time_till_dealth(ttl)
        super(UniversalToken, self).__init__(ttl, length, dports)


    def _generate_dports(self, token_size):
        """Compute an universal AT, the AT can have duplicates and order does not matter

        Args:
            N: the size of the AT, i.e. the number of destination ports

        Returns:
            A dict of the destination ports and their count
        """
        token =  {}
        cryptogen = SystemRandom()
        for _ in xrange(token_size):
            dport = cryptogen.randrange(MAX_PORT_NUMBER) + 1
            if dport not in token:
                token[dport] = 1
            else:
                token[dport] += 1
        return token


class IPBoundToken(Token):
    def __init__(self, ip, ttl, totp, length, otp_time=None):
        if not dports:
            dports = self._dict_to_array(self._generate_dports(length, ip, totp, otp_time))

        self.expire = (otp_time or time.time()) +  self.time_till_dealth(ttl, alt_time=otp_time)
        super(IPBoundToken, self).__init__(ttl, length, dports)

    def _generate_dports(token_size, ip, totp, otp_time=None):
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

        return token


class DNBotToken(object):

    def derive_key(self, password, salt=None):
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

    def token_to_string(self, token):
        return ",".join(map(str,token))

    def string_to_token(self, string):
        return map(int, string.split(","))

    def encrypt_dports(self, dports, challenge_solution, seed=None, file=None):
        """If using defense for DN-bots this will encrypt the token
        and create a challenge

        Args:
            token: the token to protect

        Returns:
            a protected token
        """
        (key, salt) = derive_key(challenge_solution)

        plaintext = token_to_string(dports)
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return (salt, iv, ciphertext, encryptor.tag)


class IPBotToken(Token):
    def __init__(self):
        pass



class UniversalIPBotToken(Token, IPBotToken):
    
    def __init__(self):
        pass

        
class UniversalDNBotToken(Token, DNBotToken):
    
    def __init__(self, ttl, challenge_solution, length=None, dports=None):
        self.challenge_solution = challenge_solution
        super(UniversalDNBotToken, self).__init__(ttl, length, dports)
        (salt, iv, ciphertext, tag) = self.encrypt_dports(self.dports)
        self.iv = iv
        self.salt = salt
        self.tag = tag
        self.ciphertext = ciphertext 

    def to_json(self):
        # Override this method so we dont return the answer
        clone = copy.deepcopy(self)
        if getattr(clone, 'challenge_solution', False):
            del clone.challenge_solution
        return jsonpickle.encode(clone, unpicklable=False)


class IPBoundDNBotToken(Token):
    def __init__(self):
        pass

class IPBoundIPBotToken(Token):
    def __init__(self):
        pass
