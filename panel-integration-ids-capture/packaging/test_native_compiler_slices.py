"""Installed compiler templates must realize the existing closed cgroup ABI."""
import configparser
import pathlib
import unittest


class CompilerSliceContractTests(unittest.TestCase):
    def test_every_template_compiler_realizes_the_closed_system_slice(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        names = (
            'panel-install@.service',
            'panel-apache-body-build@.service',
            'panel-waf-engine-build@.service',
            'panel-analytics-html-build@.service',
            'panel-app-dependencies@.service',
        )
        for name in names:
            with self.subTest(unit=name):
                # Without an explicit Slice, systemd places template instances
                # in a per-template slice, which the existing process authority
                # correctly refuses. Do not broaden the decoder to accept it.
                raw = (root / 'dev' / name).read_text()
                config = configparser.ConfigParser(interpolation=None, strict=True)
                config.read_string(raw)
                self.assertEqual(config['Service']['Slice'], 'system.slice')
                self.assertEqual(config['Service']['Type'], 'oneshot')
                self.assertEqual(config['Service']['KillMode'], 'control-group')
                self.assertEqual(config['Service']['ProtectControlGroups'], 'true')
                self.assertEqual(config['Service']['NoNewPrivileges'], 'true')
                self.assertEqual(raw.count('Slice='), 1)
                self.assertNotIn('Delegate=', raw)
                self.assertNotIn('ExecStartPre=', raw)
                self.assertNotIn('ControlGroup=', raw)


if __name__ == '__main__':
    unittest.main()
