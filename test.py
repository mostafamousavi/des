import unittest
from SimplifiedDES import Encryption

class Encryption_TEST(unittest.TestCase):
    def setUp(self):
        self.Encrr = Encryption(5,'100111000011')

    def test_simplifiedDES(self):
        sD = self.Encrr.simplifiedDES('hello world')
        self.assertEqual(sD, 'Cipher_text: LÕCÔÙD!?%9×I \n PLain_Text: HELLO WORLD ')
        

if __name__ == '__main__':
    unittest.main()