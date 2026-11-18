"""Real dependency builds: catches omitted signatures, KEM regressions and bad CLI."""
import ctypes
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(os.environ.get('PQMAGIC_SOURCE', '/home/lxh/PQMagic'))
SCRIPT = ROOT / 'scripts/build-pqmagic-aigis.sh'


class SignatureBuildTests(unittest.TestCase):
    def test_sign_build_and_legacy_build(self):
        self.assertTrue(SOURCE.is_dir(), 'set PQMAGIC_SOURCE to locked PQMagic source')
        with tempfile.TemporaryDirectory() as tmp:
            for name, options in [('kem', []), ('sign', ['--with-sign'])]:
                out = Path(tmp) / name
                result = subprocess.run(['sh', str(SCRIPT), str(SOURCE), str(out), *options],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                lib = ctypes.CDLL(str(out / 'lib/libpqmagic_std.so'))
                self.assertTrue(hasattr(lib, 'pqmagic_aigis_enc_2_std_keypair_internal'))
                for api in ['keypair_internal', 'signature_internal', 'verify_internal',
                            'signature', 'verify']:
                    self.assertEqual(hasattr(lib, 'pqmagic_aigis_sig2_std_' + api),
                                     name == 'sign', api)
                if name == 'sign':
                    self.assertIn('Test success.', (out / 'signature-correctness.log').read_text())
                    self.assertTrue((out / 'build-manifest.txt').is_file())

    def test_unknown_option_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(['sh', str(SCRIPT), str(SOURCE), tmp, '--typo'],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((Path(tmp) / 'lib/libpqmagic_std.so').exists())


if __name__ == '__main__':
    unittest.main()
