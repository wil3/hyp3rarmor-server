import unittest
from hyp3rarmor.common.generate import *

class TestProtectToken(unittest.TestCase):

    def test(self):
	#key = os.urandom(32)
        token = [1,2,3]
	(answer, salt, iv, ciphertext, tag)  =  protect_token(token)
	(key, salt) = derive_key(answer, salt)

	decryptor = Cipher(
	    algorithms.AES(key),
	    modes.GCM(iv, tag),
	    backend=default_backend()
	).decryptor()

	plaintext = decryptor.update(ciphertext) + decryptor.finalize()

	self.assertEqual(token, string_to_token(plaintext))

    

if __name__ == '__main__':
    unittest.main()
