"""Generated-shell key-install contracts with original independent expectations.

Only owned PUBLIC HOME data is used; no SSH client/server is invoked.
"""
import base64
import os
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import unittest
from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
app = load_script("initial_authorized_key_shell_workflow", ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py")

# PUBLIC wire keys below require no private key, credentials or key generation.
# The generated shell is real; expected records/receipts are not derived from it.


def public(number):
    algorithm=b'ssh-ed25519'
    blob=struct.pack('>I',len(algorithm))+algorithm+struct.pack('>I',32)+bytes([number])*32
    return 'ssh-ed25519 '+base64.b64encode(blob).decode()+' fixture-'+str(number)


class KeyShellWorkflowTests(unittest.TestCase):
    def install(self,home,lines,*,bad_payload=False,copy_error=False):
        entries=[dict(name='key'+str(i)+'.pub',line=line,fingerprint=app._public_key_fingerprint(line))
                 for i,line in enumerate(lines)]
        argv=app.key_install_command(entries)
        self.assertEqual(app.ib_command_argv(argv),argv)
        if bad_payload: argv[-1]='===='
        # Bind only the remote-home expansions to a private test directory;
        # do not change this machine's HOME or invoke ssh/any network tool.
        script=argv[2].replace('"${HOME:-}"',shlex.quote(str(home))).replace(
            '"$HOME"',shlex.quote(str(home))).replace('"$HOME/.ssh"',shlex.quote(str(home/'.ssh')))
        self.assertNotIn('$HOME',script)
        if copy_error:
            statement='cat "$auth" >"$staged";'
            self.assertIn(statement,script)
            script=script.replace(statement,statement+' false;')
        return subprocess.run([argv[0],'-c',script,*argv[3:]],capture_output=True,text=True,timeout=5,cwd=home,env={'HOME':str(home),'PATH':os.defpath,'LC_ALL':'C','LANG':'C'},check=False)

    def test_no_final_newline_does_not_concatenate_existing_and_requested_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder); ssh=home/'.ssh'; ssh.mkdir()
            auth=ssh/'authorized_keys'; auth.write_text(public(1))
            result=self.install(home,[public(2),public(3)])
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(auth.read_text().splitlines(),[public(1),public(2),public(3)])
            self.assertEqual(result.stdout,'IBSW_PUBLIC_KEYS_UPDATED\n')

    def test_second_install_is_unchanged_keeps_inode_and_does_not_grow_blank_lines(self):
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder)
            first=self.install(home,[public(2),public(3)])
            auth=home/'.ssh/authorized_keys'; original=auth.read_bytes(); inode=auth.stat().st_ino
            auth.chmod(0o644)
            second=self.install(home,[public(2),public(3)])
            self.assertEqual(first.returncode,0,first.stderr)
            self.assertEqual(second.returncode,0,second.stderr)
            self.assertEqual(second.stdout,'IBSW_PUBLIC_KEYS_UNCHANGED\n')
            self.assertEqual(auth.read_bytes(),original)
            self.assertEqual(auth.stat().st_ino,inode)
            self.assertEqual(auth.stat().st_mode&0o777,0o600)

    def test_options_and_unrelated_keys_are_preserved_and_requested_keys_are_unique(self):
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder); (home/'.ssh').mkdir()
            restricted='no-agent-forwarding '+public(2)
            (home/'.ssh/authorized_keys').write_text('# owner note\n'+restricted+'\n'+public(1)+'\n')
            result=self.install(home,[public(2),public(3)])
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual((home/'.ssh/authorized_keys').read_text().splitlines(),
                ['# owner note',restricted,public(1),public(3)])

    def test_authorized_keys_symlink_is_refused_without_touching_target(self):
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder); (home/'.ssh').mkdir()
            foreign=home/'foreign'; foreign.write_text('do not alter\n')
            (home/'.ssh/authorized_keys').symlink_to(foreign)
            result=self.install(home,[public(2)])
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(foreign.read_text(),'do not alter\n')
            self.assertNotIn('IBSW_PUBLIC_KEYS_UPDATED',result.stdout)

    def test_ssh_directory_symlink_is_refused_without_touching_foreign_content(self):
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder); foreign=home/'foreign'; foreign.mkdir()
            (foreign/'authorized_keys').write_text(public(1)+'\n')
            (home/'.ssh').symlink_to(foreign,target_is_directory=True)
            result=self.install(home,[public(2)])
            self.assertNotEqual(result.returncode,0)
            self.assertEqual((foreign/'authorized_keys').read_text(),public(1)+'\n')
            self.assertEqual(sorted(p.name for p in foreign.iterdir()),['authorized_keys'])

    def test_decoder_failure_never_replaces_old_authorization_and_cleans_private_temporaries(self):
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder); (home/'.ssh').mkdir()
            auth=home/'.ssh/authorized_keys'; auth.write_text(public(1)+'\n')
            result=self.install(home,[public(2)],bad_payload=True)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(auth.read_text(),public(1)+'\n')
            self.assertEqual(result.stdout,'')
            self.assertEqual(sorted(p.name for p in auth.parent.iterdir()),['authorized_keys'])

    def test_existing_authorization_copy_failure_cannot_be_masked_by_successful_awk(self):
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder); (home/'.ssh').mkdir()
            auth=home/'.ssh/authorized_keys'; auth.write_text(public(1)+'\n'+public(2)+'\n')
            result=self.install(home,[public(2)],copy_error=True)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(auth.read_text(),public(1)+'\n'+public(2)+'\n')
            self.assertEqual(result.stdout,'')
            self.assertEqual(sorted(p.name for p in auth.parent.iterdir()),['authorized_keys'])


if __name__ == "__main__":
    unittest.main()
