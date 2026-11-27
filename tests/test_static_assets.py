from pathlib import Path
import shutil
import subprocess
import unittest

from svcdash.privacy import sanitize_text


@unittest.skipUnless(shutil.which('node'), 'Node.js is required to validate dashboard scripts')
class StaticAssetsTest(unittest.TestCase):
    def test_vendored_scripts_remain_valid_after_public_export_sanitization(self):
        assets = Path(__file__).resolve().parents[1] / 'static' / 'magpie-native'
        invalid = []
        for script in sorted(assets.rglob('*.js')):
            source = sanitize_text(script.read_text(encoding='utf-8'), source_code=True)
            result = subprocess.run(['node', '--check', '--input-type=module'],
                                    input=source, text=True, capture_output=True)
            if result.returncode:
                invalid.append(str(script.relative_to(assets)))
        self.assertEqual(invalid, [])
