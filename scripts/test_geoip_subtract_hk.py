import ipaddress
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import geoip_subtract_hk as script


def category(code, networks, extra=b""):
    payload = script.message(1, code.encode("ascii"))
    for text in networks:
        network = ipaddress.ip_network(text)
        cidr = script.message(1, network.network_address.packed)
        cidr += b"\x10" + script.encode_varint(network.prefixlen)
        payload += script.message(2, cidr)
    return script.message(1, payload + extra)


def category_payloads(data):
    return {script.country_code(value): value
            for number, wire, value, _ in script.fields(data)
            if number == 1 and wire == 2}


class PostprocessTests(unittest.TestCase):
    def test_subtracts_ipv4_and_ipv6_and_preserves_other_data(self):
        metadata = b"\x22\x04note"
        unknown = b"\x3a\x04root"
        cn = category("CN", ["8.210.0.0/16", "223.5.5.0/24", "2001:db8::/32"], metadata)
        hk = category("HK", ["8.210.0.0/17", "2001:db8:8000::/33"])
        other = category("PRIVATE", ["10.0.0.0/8"])
        original = cn + hk + other + unknown
        result, removed = script.postprocess(original)
        payloads = category_payloads(result)
        actual = {str(network) for network in script.prefixes(payloads["CN"])}
        self.assertEqual(actual, {"8.210.128.0/17", "223.5.5.0/24", "2001:db8::/33"})
        self.assertEqual(removed, {4: 32768, 6: 2 ** 95})
        self.assertIn(metadata, payloads["CN"])
        self.assertTrue(result.endswith(hk + other + unknown))
        self.assertEqual(script.postprocess(result), (result, {4: 0, 6: 0}))

    def test_overlapping_cidrs_are_subtracted_by_address(self):
        original = category("CN", ["8.210.0.0/16", "8.210.0.0/17"])
        original += category("HK", ["8.210.0.0/18", "8.210.32.0/19", "8.210.192.0/18"])
        result, removed = script.postprocess(original)
        actual = {str(n) for n in script.prefixes(category_payloads(result)["CN"])}
        self.assertEqual(actual, {"8.210.64.0/18", "8.210.128.0/18"})
        self.assertEqual(removed[4], 32768)

    def test_hk_can_remove_the_entire_cn_category(self):
        original = category("CN", ["8.210.0.0/17"])
        original += category("HK", ["8.210.0.0/16"])
        result, _ = script.postprocess(original)
        payloads = category_payloads(result)
        self.assertIn("CN", payloads)
        self.assertEqual(script.prefixes(payloads["CN"]), [])

    def test_no_overlap_keeps_the_original_bytes(self):
        original = category("CN", ["223.5.5.0/24"])
        original += category("HK", ["8.210.0.0/16"])
        self.assertEqual(script.postprocess(original), (original, {4: 0, 6: 0}))

    def test_rejects_missing_duplicate_and_reversed_categories(self):
        cn = category("CN", ["223.5.5.0/24"])
        hk = category("HK", ["8.210.0.0/16"])
        for original in (cn, cn + cn + hk, cn + category("HK", [], b"\x18\x01")):
            with self.subTest(original=original), self.assertRaises(ValueError):
                script.postprocess(original)

    def test_failed_processing_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "raw.dat"
            output = Path(directory) / "geoip.dat"
            source.write_bytes(b"\x0a\x80")
            output.write_bytes(b"existing output")
            result = subprocess.run([sys.executable, str(Path(script.__file__)),
                                     str(source), str(output)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"error:", result.stderr)
            self.assertEqual(output.read_bytes(), b"existing output")
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()),
                             ["geoip.dat", "raw.dat"])

    def test_cli_can_repeat_an_update_without_modifying_the_download(self):
        original = category("CN", ["8.210.0.0/16"])
        original += category("HK", ["8.210.0.0/17"])
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "raw.dat"
            output = Path(directory) / "geoip.dat"
            source.write_bytes(original)
            command = [sys.executable, str(Path(script.__file__)), str(source), str(output)]
            subprocess.run(command, check=True, capture_output=True)
            first = output.read_bytes()
            subprocess.run(command, check=True, capture_output=True)
            self.assertEqual(output.read_bytes(), first)
            self.assertEqual(source.read_bytes(), original)
            same_path = subprocess.run(command[:-1] + [str(source)], capture_output=True)
            self.assertNotEqual(same_path.returncode, 0)
            self.assertEqual(source.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
