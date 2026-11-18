"""Actual pki subprocesses: keys, CSR, traditional/compound CA chains and digest policy."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PKI = ['sh', str(ROOT / 'scripts/pki-local.sh')]


class PkiTests(unittest.TestCase):
    def test_certificates_and_restart_matching(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            def pki(*args, data=None, okay=True):
                p = subprocess.run([*PKI, *args], input=data, capture_output=True)
                self.assertEqual(p.returncode == 0, okay, p.stderr.decode(errors='replace'))
                return p.stdout
            def write(name, data):
                path = d / name
                path.write_bytes(data)
                return str(path)
            for kind in ['aigissig2sm3', 'aigissig2ed25519']:
                key = pki('--gen', '--type', kind, '--outform', 'pem')
                keyfile = write(kind + '.key', key)
                pub = pki('--pub', '--type', kind, '--in', keyfile)
                self.assertEqual(pub, pki('--pub', '--type', 'priv', '--in', keyfile))
                self.assertIn(b'AIGIS_SIG2', pki('--print', '--type', kind, '--in', keyfile))
                pki('--self', '--type', kind, '--in', keyfile, '--dn', 'CN=test', '--digest', 'sha256', okay=False)
                pki('--gen', '--type', kind, '--size', '512', okay=False)
            leafkey = str(d / 'aigissig2ed25519.key')
            request = write('request.der', pki('--req', '--type', 'aigissig2ed25519',
                           '--in', leafkey, '--dn', 'CN=moon', '--san', 'moon.test'))
            for kind in ['ed25519', 'aigissig2ed25519']:
                cakey = write(kind + '-ca.key', pki('--gen', '--type', kind, '--outform', 'pem'))
                ca = write(kind + '-ca.pem', pki('--self', '--type', kind, '--in', cakey,
                           '--dn', 'CN=' + kind + '-ca', '--ca', '--lifetime', '365', '--outform', 'pem'))
                cert = write(kind + '-leaf.pem', pki('--issue', '--type', 'pkcs10', '--in', request,
                             '--cacert', ca, '--cakey', cakey, '--lifetime', '30', '--outform', 'pem'))
                self.assertEqual(pki('--pub', '--type', 'x509', '--in', cert),
                                 pki('--pub', '--type', 'priv', '--in', leafkey))
                pki('--verify', '--in', cert, '--cacert', ca)
                pki('--print', '--in', cert)
                if kind == 'aigissig2ed25519':
                    certder = pki('--issue', '--type', 'pkcs10', '--in', request,
                                  '--cacert', ca, '--cakey', cakey)
                    inspected = subprocess.run(['openssl', 'x509', '-inform', 'der', '-noout', '-text'],
                                               input=certder, capture_output=True)
                    self.assertEqual(inspected.returncode, 0, inspected.stderr.decode())
                    self.assertTrue(b'Digital Signature' in inspected.stdout, 'composite leaf must contain digitalSignature keyUsage')
                    def tlv(data, offset):
                        start = offset
                        tag, length = data[offset:offset+2]
                        offset += 2
                        if length & 128:
                            n = length & 127
                            length = int.from_bytes(data[offset:offset+n], 'big')
                            offset += n
                        return tag, offset, offset+length
                    _, outer, _ = tlv(certder, 0)
                    _, _, tbs_end = tlv(certder, outer)
                    _, _, alg_end = tlv(certder, tbs_end)
                    _, bits, _ = tlv(certder, alg_end)
                    def sequence(body):
                        n = len(body)
                        return b'\x30\x82' + n.to_bytes(2, 'big') + body
                    def malformed_wrappers(data, outer, start):
                        _, bits_body, end = tlv(data, start)
                        size = end-bits_body
                        nonminimal = b'\x03\x83\x00' + size.to_bytes(2,'big') + data[bits_body:end]
                        return [sequence(data[outer:start] + nonminimal),
                                sequence(data[outer:] + b'\x05\x00')]
                    for number, malformed in enumerate(malformed_wrappers(certder,outer,alg_end)):
                        invalid = write('malformed-cert-' + str(number) + '.der', malformed)
                        pki('--print', '--in', invalid, okay=False)
                    damaged = bytearray(certder)
                    damaged[bits] = 1
                    invalid = write('invalid-bits.der', damaged)
                    pki('--verify', '--in', invalid, '--cacert', ca, okay=False)
                    damaged[bits] = 0
                    damaged[bits+1] ^= 1
                    invalid = write('invalid-signature.der', damaged)
                    pki('--verify', '--in', invalid, '--cacert', ca, okay=False)
                    invalid = write('trailing-certificate.der', certder + b'\x00')
                    pki('--print', '--in', invalid, okay=False)
                    reqder = Path(request).read_bytes()
                    _, outer, _ = tlv(reqder, 0)
                    _, _, info_end = tlv(reqder, outer)
                    _, _, alg_end = tlv(reqder, info_end)
                    _, bits, _ = tlv(reqder, alg_end)
                    for number, malformed in enumerate(malformed_wrappers(reqder,outer,alg_end)):
                        invalid = write('malformed-csr-' + str(number) + '.der', malformed)
                        pki('--issue', '--type', 'pkcs10', '--in', invalid,
                            '--cacert', ca, '--cakey', cakey, okay=False)
                    damaged = bytearray(reqder)
                    damaged[bits] = 1
                    invalid = write('invalid-csr.der', damaged)
                    pki('--issue', '--type', 'pkcs10', '--in', invalid,
                        '--cacert', ca, '--cakey', cakey, okay=False)

                # A different root must not validate this leaf.
                wrongkey = write('wrong.key', pki('--gen', '--type', kind))
                wrongca = write('wrong.der', pki('--self', '--type', kind, '--in', wrongkey,
                                '--dn', 'CN=wrong', '--ca'))
                pki('--verify', '--in', cert, '--cacert', wrongca, okay=False)


if __name__ == '__main__':
    unittest.main()
