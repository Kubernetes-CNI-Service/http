"""Stage1 project-key template and refusal controls, not native installation."""
import base64,importlib.util,struct,sys,unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'tools/ufm_project_key_install.py'
FACTS=[]
def public_line(byte,comment):
    algorithm=b'ssh-ed25519'
    wire=struct.pack('>I',len(algorithm))+algorithm+struct.pack('>I',32)+bytes([byte])*32
    return algorithm+b' '+base64.b64encode(wire)+b' '+comment+b'\n'
MANAGEMENT=public_line(21,b'management-project')
LAPTOP=public_line(22,b'laptop-project')

def subject(test):
    test.assertTrue(SOURCE.is_file(),'Fixed stage1 key-install template API is missing')
    name='f01_project_key_install_test_subject'
    spec=importlib.util.spec_from_file_location(name,SOURCE)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    spec.loader.exec_module(module)
    return module

class F01ProjectKeyInstallDirectTests(unittest.TestCase):
    def test_fixed_two_key_script_uses_original_home_contract_and_public_data_only(self):
        api=subject(self)
        raw=api.render_project_key_install_script(MANAGEMENT,LAPTOP)
        self.assertIs(type(raw),bytes)
        self.assertTrue(raw.startswith(b'#!/usr/bin/env bash\nset -euo pipefail\n'))
        self.assertIn(b'test ! -L "$HOME"',raw)
        self.assertIn(b'auth="$ssh_dir/authorized_keys"',raw)
        self.assertIn(b'mv -f "$tmp" "$auth"',raw)
        self.assertIn(b'F01_PROJECT_KEYS_INSTALLED_NOT_DEPLOYED',raw)
        self.assertNotIn(b'management-project',raw)
        self.assertNotIn(b'laptop-project',raw)
        identities=b' '.join(MANAGEMENT.split()[:2])+b'\n'+b' '.join(LAPTOP.split()[:2])+b'\n'
        self.assertIn(base64.b64encode(identities),raw)
        # Every external utility is checked BEFORE modifying HOME/.ssh.
        for command in (b'mkdir',b'chmod',b'mktemp',b'cat',b'base64',b'awk',b'cmp',b'mv',b'rm'):
            probe=b'command -v '+command+b' >/dev/null'
            self.assertIn(probe,raw)
            self.assertLess(raw.index(probe),raw.index(b'mkdir -p "$ssh_dir"'))
        self.assertNotIn(b'sudo',raw)
        self.assertNotIn(b'accept-new',raw)
        self.assertNotIn(b'passwd',raw)
        # Backup is a separate retained original, not the candidate or atomic mv.
        self.assertIn(b'stage_dir="$HOME/.xdr-key-stage-',raw)
        self.assertIn(b'mkdir -m 700 "$stage_dir"',raw)
        self.assertIn(b'set -C; cat "$auth" > "$backup"',raw)
        self.assertIn(b'cmp -s "$auth" "$backup"',raw)
        self.assertLess(raw.index(b'cmp -s "$auth" "$backup"'),raw.index(b'tmp="$(mktemp'))
        self.assertIn(b'F01_BLOCKED_BACKUP',raw)
        self.assertIn(b'NO_PRIOR_CONFIG',raw)
        self.assertIn(b'trap \'rm -f "$tmp"\' EXIT\n',raw)
        self.assertIn(b'trap \'exit 143\' TERM\n',raw)
        self.assertNotIn(b'EXIT HUP INT TERM',raw)
        FACTS.append({'control':'fixed_public_template','native_installation':False})

    def test_duplicate_or_noncanonical_project_public_key_cannot_form_installation_script(self):
        api=subject(self)
        with self.assertRaises(api.ProjectKeyInstallHold):
            api.render_project_key_install_script(MANAGEMENT,MANAGEMENT)
        with self.assertRaises(api.ProjectKeyInstallHold):
            api.render_project_key_install_script(MANAGEMENT,LAPTOP+b'printf SECRET\n')
        FACTS.append({'control':'public_input_refusal','native_installation':False})

    def test_default_or_unknown_password_outcome_is_refused_without_an_installation_result(self):
        api=subject(self)
        for reply,rejections in (('authenticated',1),('unknown',0),('rejected',1),('authenticated',True)):
            with self.subTest(reply=reply,rejections=rejections):
                with self.assertRaises(api.ProjectKeyInstallHold):
                    api.require_new_password_authentication(reply,rejections)
        self.assertIsNone(api.require_new_password_authentication('authenticated',0))
        FACTS.append({'control':'change_required_refusal','native_installation':False})
    def test_live_entry_rejects_incomplete_password_inputs_before_any_connection(self):
        from unittest import mock
        from tools import ufm_bootstrap_auth_adapter as auth
        entry=getattr(auth,'establish_project_direct_management_key_access',None)
        self.assertTrue(callable(entry),'Fixed live project-key installation entry is missing')
        with mock.patch.object(auth,'_direct_ipv4_connected_stream') as connect:
            with self.assertRaises(auth.BootstrapAuthError):
                entry(ROOT,'192.0.2.21',ROOT/'NOT_READ_known','0'*64,ROOT/'NOT_READ_private',
                      new_password='SAME_EPHEMERAL',default_password='SAME_EPHEMERAL',timeout=10)
            self.assertEqual(0,connect.call_count)
        FACTS.append({'control':'live_input_refusal','native_installation':False})
