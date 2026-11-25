import unittest
from gate import refusal, validate_result, FALSE_CLAIMS

class FailClosedTests(unittest.TestCase):
    def test_expected_refusal(self):
        self.assertTrue(validate_result(refusal()))
    def test_not_an_os_grade(self):
        result = refusal()
        for field in FALSE_CLAIMS:
            self.assertIs(result[field], False)
    def test_forged_approval(self):
        for field in FALSE_CLAIMS:
            result = refusal()
            result[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_result(result)
    def test_forged_status(self):
        result = refusal()
        result["status"] = "PASS"
        with self.assertRaises(ValueError):
            validate_result(result)
    def test_forged_interlock(self):
        result = refusal()
        result["interlock"] = "OPEN"
        with self.assertRaises(ValueError):
            validate_result(result)
    def test_forged_r13(self):
        result = refusal()
        result["r13_receipt_verified"] = True
        with self.assertRaises(ValueError):
            validate_result(result)
