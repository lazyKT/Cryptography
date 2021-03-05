import unittest
from aes import AES


class TestAES (unittest.TestCase):

  def test_user_defined_key (self):
    """
    : Test AES128 using user-defined key
    """
    aes = AES()
    plaintext = "Simply the best!"
    key = "ThisIsSecret"
    aes.set_key(key)
    c = aes.cipher(0, plaintext) # Mode 0 : Encrypt
    m = aes.cipher(1, c) # Mode 1 : Decrypt
    self.assertEqual(plaintext, m, "Test 1 using user-defined key : Failed!")

  def test_random_key (self):
    """
    : Test AES128 using randomly generated key
    """
    aes = AES()
    plaintext = "AES is coolest!"
    aes.gen_key()
    c = aes.cipher (0, plaintext) # Mode 0 : Encrypt
    m = aes.cipher (1, c) # Mode 1 : Decrypt
    self.assertEqual(plaintext, m, "Test 2 using random key : Failed!")


if __name__ == '__main__':
  unittest.main()
