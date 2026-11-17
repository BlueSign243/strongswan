"""Check asynchronous rekey waiting without requiring a running daemon."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[2] / "testing/hosts/default/usr/local/bin/expect-rekey"


class RekeyWaitTests(unittest.TestCase):
    def run_helper(self, kind, stuck=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "swanctl"
            fake.write_text("""#!/usr/bin/env python3
import os, sys
from pathlib import Path
state = Path(os.environ['REKEY_TEST_STATE'])
count = int(state.read_text()) if state.exists() else -1
if sys.argv[1] == '--rekey':
    state.write_text('0')
    sys.exit(0)
if count >= 0:
    state.write_text(str(count + 1))
new = count >= 2 and os.environ['REKEY_TEST_STUCK'] != 'yes'
ident = 2 if new else 1
print(f'host-host: #{ident}, ESTABLISHED, IKEv2, abc_i def_r')
print(f'  host-host: #{ident}, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-256')
""")
            fake.chmod(0o755)
            result = subprocess.run(
                ["bash", str(HELPER), kind, "host-host"],
                env={**os.environ, "PATH": f"{directory}:{os.environ['PATH']}",
                     "REKEY_TEST_STATE": str(root / "state"),
                     "REKEY_TEST_STUCK": "yes" if stuck else "no",
                     "REKEY_WAIT_STEPS": "4", "REKEY_WAIT_INTERVAL": "0"},
                text=True, capture_output=True,
            )
            return result

    def test_waits_for_new_child_id(self):
        result = self.run_helper("child")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Rekeyed child host-host: 1 -> 2", result.stdout)

    def test_waits_for_new_ike_id(self):
        result = self.run_helper("ike")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Rekeyed ike host-host: 1 -> 2", result.stdout)

    def test_old_installed_sa_is_not_success(self):
        result = self.run_helper("child", stuck=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not replace", result.stderr)


if __name__ == "__main__":
    unittest.main()
