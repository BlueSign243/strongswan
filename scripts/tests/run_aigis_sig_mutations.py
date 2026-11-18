"""Compile isolated mutant plugins; never modify checkout source or normal binaries."""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / 'src/libstrongswan/plugins/pqmagic'
PREFIX = ROOT / '.local-pqmagic/sign'
source = (PLUGIN / 'pqmagic_composite_sig.c').read_text()
assert source.count('return a && b;') == 1
for expression in ['a', 'b']:
    with tempfile.TemporaryDirectory(prefix='aigis-mutation-') as tmp:
        root = Path(tmp)
        for directory in (ROOT / 'src/libstrongswan/plugins').iterdir():
            if directory.is_dir() and directory.name != 'pqmagic':
                (root / directory.name).symlink_to(directory, target_is_directory=True)
        target = root / 'pqmagic/.libs'
        target.mkdir(parents=True)
        mutant = root / 'mutant.c'
        mutant.write_text(source.replace('return a && b;', 'return ' + expression + ';'))
        subprocess.run([os.environ.get('CC', 'cc'), '-O1', '-fPIC', '-shared',
            '-include', str(ROOT / 'config.h'), '-I' + str(ROOT / 'src/libstrongswan'),
            '-I' + str(PLUGIN), '-I' + str(PREFIX / 'include'),
            *[str(PLUGIN / filename) for filename in ['pqmagic_plugin.c', 'pqmagic_kem.c',
              'pqmagic_aigis_sig.c', 'pqmagic_sig_encoding.c']], str(mutant),
            '-L' + str(PREFIX / 'lib'), '-Wl,-rpath,' + str(PREFIX / 'lib'), '-lpqmagic_std',
            '-o', str(target / 'libstrongswan-pqmagic.so')], check=True)
        conf = root / 'tests.conf'
        conf.write_text('tests {\n  plugindir = ' + str(root) + '\n}\n')
        env = dict(os.environ, STRONGSWAN_CONF=str(conf), TESTS_SUITES='composite_aigis_sig',
                   TESTS_FUNCTIONS='test_signature_vectors')
        result = subprocess.run([str(ROOT / 'src/libstrongswan/tests/libstrongswan_tests')],
                                env=env, capture_output=True, text=True)
        assert result.returncode != 0, 'mutant was accepted: ' + expression
        assert "Failure in 'test_signature_vectors'" in result.stdout + result.stderr, result.stdout + result.stderr
        print('Mutant requiring only component ' + expression + ': rejected by signature_vectors')
