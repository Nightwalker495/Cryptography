import unittest
from vigenere import TextStripper
from vigenere import VigenereCipher


class TextStripperTest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__text = None

    def test_strip_lowercase_letters_only(self):
        self.__given_text('abcdefgh')
        self.__then_stripped_text_equals('abcdefgh')

    def test_strip_uppercase_letters_only(self):
        self.__given_text('ABCDEFG')
        self.__then_stripped_text_equals('ABCDEFG')

    def test_strip_mixedcase_letters(self):
        self.__given_text('aBcDeFgH')
        self.__then_stripped_text_equals('aBcDeFgH')

    def test_strip_mixedcase_with_dots(self):
        self.__given_text('...a.B.c.D...')
        self.__then_stripped_text_equals('aBcD')

    def test_strip_mixedcase_with_spaces(self):
        self.__given_text('   a B c D   ')
        self.__then_stripped_text_equals('aBcD')

    def test_strip_mixedcase_with_spaces_commas_quotes_dots(self):
        self.__given_text('   .."a" B, c,,.. "...D..."   ')
        self.__then_stripped_text_equals('aBcD')

    def __given_text(self, text):
        self.__text = text

    def __then_stripped_text_equals(self, expected_stripped_text):
        stripped_text = TextStripper.strip_non_alpha(self.__text)
        self.assertEquals(stripped_text, expected_stripped_text)


class VigenereCipherTest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__text = None
        self.__password = None

    def test_one_char_password_uppercase(self):
        self.__given_text_and_password('BBBB', 'B')
        self.__then_decrypted_text_equals('AAAA')

    def test_two_char_password_uppercase(self):
        self.__given_text_and_password('BCBC', 'BC')
        self.__then_decrypted_text_equals('AAAA')

    def test_two_char_password_mixedcase(self):
        self.__given_text_and_password('BcBc', 'bC')
        self.__then_decrypted_text_equals('AaAa')

    def test_no_change(self):
        self.__given_text_and_password('something', 'AAA')
        self.__then_decrypted_text_equals('something')

    def test_mixedcase_with_spaces_commas_quotes_dots(self):
        self.__given_text_and_password('"I concur", said John...', 'aBc')
        self.__then_decrypted_text_equals('"I bmnbsr", ryic Hogl...')

    def test_exception_for_empty_password(self):
        self.__given_text_and_password('nothing special', '')
        self.__then_exception_is_raised_for_decryption(ValueError)

    def test_exception_password_contains_nonalpha_chars(self):
        self.__given_text_and_password('nothing special', 'a0b1c2...')
        self.__then_exception_is_raised_for_decryption(ValueError)

    def __given_text_and_password(self, text, password):
        self.__text = text
        self.__password = password

    def __then_decrypted_text_equals(self, expected_decrypted_text):
        decrypted_text = VigenereCipher.decrypt(self.__text, self.__password)
        self.assertEquals(decrypted_text, expected_decrypted_text)

    def __then_exception_is_raised_for_decryption(self, expected_exception):
        self.assertRaises(expected_exception, VigenereCipher.decrypt,
                          self.__text, self.__password)
