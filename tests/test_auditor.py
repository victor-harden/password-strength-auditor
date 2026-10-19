import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import auditor


class AuditorTests(unittest.TestCase):
    def test_common_password_scores_zero(self):
        score, _, _ = auditor.score_password("password")
        self.assertEqual(score, 0)

    def test_short_password_is_weak(self):
        score, bits, _ = auditor.score_password("Ab3!")
        self.assertLess(score, 3)
        self.assertLess(bits, 40)

    def test_long_random_password_passes(self):
        score, bits, _ = auditor.score_password("vN7#qL2$wR9@tY4!kM8&")
        self.assertGreaterEqual(score, 3)
        self.assertGreaterEqual(bits, 80)

    def test_sequences_detected(self):
        patterns = auditor.find_patterns("abcdEfgh1234")
        self.assertIn("sequence", patterns)

    def test_repeated_block_detected(self):
        patterns = auditor.find_patterns("abcabcabc")
        self.assertIn("repeated-block", patterns)

    def test_entropy_grows_with_length(self):
        self.assertLess(auditor.entropy_bits("abc"), auditor.entropy_bits("abcdefgh"))

    def test_cli_json_and_exit_code(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = auditor.main(["--password", "vN7#qL2$wR9@tY4!kM8&", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertGreaterEqual(payload["score"], 3)

    def test_cli_weak_password_exit_code(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(auditor.main(["--password", "qwerty"]), 1)


if __name__ == "__main__":
    unittest.main()
