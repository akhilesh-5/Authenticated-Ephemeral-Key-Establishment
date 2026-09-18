import unittest
from protocol import aad, canonical_transcript, derive_keys, nonce


class ProtocolTests(unittest.TestCase):
    def test_transcript_is_124_bytes(self):
        value = canonical_transcript("ALICE001", "BOB00001", b"a" * 16, b"b" * 16, b"c" * 32, b"d" * 32)
        self.assertEqual(len(value), 124)

    def test_directional_keys_are_distinct(self):
        keys = derive_keys(b"x" * 32, b"y" * 32)
        self.assertEqual(len(keys[0]), 32)
        self.assertEqual(len(keys[1]), 32)
        self.assertNotEqual(*keys)

    def test_nonce_and_aad_are_deterministic(self):
        self.assertEqual(nonce(0), b"\0\0\0\0" + b"\0" * 8)
        self.assertEqual(len(aad("ALICE001", "BOB00001", b"a" * 16, b"b" * 16, "ALICE001", "BOB00001", 0)), 56)


if __name__ == "__main__":
    unittest.main()
