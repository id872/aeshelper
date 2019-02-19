#!/usr/bin/env python3.6

from json import dumps
from random import choice, randint
from string import printable
from unittest import TestCase, main as unittest_main

from aeshelper.aeshelper import AesHelper, OutputFmt


class TestAesHelper(TestCase):
    @staticmethod
    def get_random_string(length):
        return ''.join(choice(printable) for _ in range(length))

    def test_encrypt_random_strings(self):
        def do_test(aes_helper, str_len_min, str_len_max):
            for counter in range(str_len_min, str_len_max):
                random_string = TestAesHelper.get_random_string(counter)

                encrypted = aes_helper.encrypt_str(random_string)
                decrypted = aes_helper.decrypt(encrypted)
                self.assertEqual(random_string, decrypted)

        for enc_fmt in OutputFmt:
            AesHelper.enc_out_fmt = enc_fmt
            do_test(AesHelper('this key should be strong!'), str_len_min=1, str_len_max=17)
            do_test(AesHelper('this key should be strong!'), str_len_min=102, str_len_max=108)
            do_test(AesHelper('this key should be strong!'), str_len_min=1323, str_len_max=1330)

    def test_encrypt_json_data(self):
        def get_random_json_data():
            dict_keys_count = 600
            json_rand_data = {}

            for counter in range(dict_keys_count):
                json_rand_data[f'#{counter}#'] = TestAesHelper.get_random_string(randint(10, 1000))

            return json_rand_data

        for enc_fmt in OutputFmt:
            AesHelper.enc_out_fmt = enc_fmt
            aes_helper = AesHelper('this key should be strong!')
            json_data = get_random_json_data()

            encrypted = aes_helper.encrypt_json(json_data)

            self.assertEqual(dumps(json_data), aes_helper.decrypt(encrypted))

    def test_encrypt_empty_string(self):
        aes_helper = AesHelper('this key should be strong!')

        self.assertRaises(ValueError, aes_helper.encrypt_str, '')

    def test_encrypt_empty_json(self):
        aes_helper = AesHelper('this key should be strong!')

        self.assertRaises(ValueError, aes_helper.encrypt_json, {})

    def test_decryption_no_iv(self):
        aes_helper = AesHelper('this key should be strong!')
        string_data = 'data data data to encrypt'

        for enc_fmt in OutputFmt:
            AesHelper.enc_out_fmt = enc_fmt
            encrypted = aes_helper.encrypt_str(string_data)
            aes_helper.init_vector = None
            self.assertRaises(ValueError, aes_helper.decrypt, encrypted)

    def test_decryption_failed(self):
        aes_helper = AesHelper('this key should be strong! (for encryption)')
        string_data = 'data data data to encrypt'

        for enc_fmt in OutputFmt:
            AesHelper.enc_out_fmt = enc_fmt
            encrypted = aes_helper.encrypt_str(string_data)

            self.assertEqual(string_data, aes_helper.decrypt(encrypted))

            aes_helper.set_key('setting other key for decryption fail')
            self.assertNotEqual(string_data, aes_helper.decrypt(encrypted))

            aes_helper.set_key('this key should be strong! (for encryption)')
            self.assertEqual(string_data, aes_helper.decrypt(encrypted))

    def test_concatenated_iv_enc(self):
        aes_helper = AesHelper('this key should be strong!')
        string_data = 'data data data to encrypt'

        for enc_fmt in OutputFmt:
            AesHelper.enc_out_fmt = enc_fmt
            encrypted = aes_helper.encrypt_str(string_data, iv_concat=True)

            self.assertEqual(string_data,
                             aes_helper.decrypt(encrypted, contains_iv=True))
            self.assertNotEqual(string_data,
                                aes_helper.decrypt(encrypted, contains_iv=False))


if __name__ == '__main__':
    unittest_main()
