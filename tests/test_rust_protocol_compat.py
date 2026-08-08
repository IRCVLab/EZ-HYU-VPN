import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hyu_vpn.status import VpnStatus


class RustProtocolCompatibilityTests(unittest.TestCase):
    def test_shared_status_fixture_round_trips_exact_python_schema(self):
        fixture = json.loads((ROOT / "tests/fixtures/vpn-status-v1.json").read_text(encoding="utf-8"))
        self.assertEqual(VpnStatus.from_dict(fixture).to_dict(), fixture)


if __name__ == "__main__":
    unittest.main()
