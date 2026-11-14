import unittest
import app


class BalanceFormatting(unittest.TestCase):
    def test_balances_round_down_to_the_cent(self):
        self.assertEqual(app._usd("26.999998"), "$26.99")
        self.assertEqual(app._usd("100.123456"), "$100.12")
        self.assertEqual(app._usd("0.009999"), "$0.00")
        self.assertEqual(app._usd("1.005"), "$1.00")        # never rounds half up

    def test_exact_amounts_are_unchanged(self):
        self.assertEqual(app._usd("1234.5"), "$1,234.50")
        self.assertEqual(app._usd("100"), "$100.00")
        self.assertEqual(app._usd("0"), "$0.00")

    def test_bad_input_shows_a_dash(self):
        self.assertEqual(app._usd(None), "—")
        self.assertEqual(app._usd("abc"), "—")


class ReceiptAmounts(unittest.TestCase):
    def test_amounts_are_exact_with_at_least_two_decimals(self):
        self.assertEqual(app._amount("420"), "420.00")
        self.assertEqual(app._amount("75.5"), "75.50")
        self.assertEqual(app._amount("10.15678"), "10.15678")      # a receipt never rounds
        self.assertEqual(app._amount("1234567.1"), "1,234,567.10")
        self.assertEqual(app._amount("100"), "100.00")
        self.assertEqual(app._amount("0.000001"), "0.000001")

    def test_bad_input_shows_a_dash(self):
        self.assertEqual(app._amount(None), "—")
        self.assertEqual(app._amount("abc"), "—")


if __name__ == "__main__":
    unittest.main()
