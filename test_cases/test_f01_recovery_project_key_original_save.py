"""Single actual local original save control; no SDK/native permission proof."""
import hashlib,os,tempfile,unittest
from pathlib import Path
from tools import ufm_project_key_install as keys
FACTS=[]
RAW=b'REMOTE_COPY_MATCHED_NOT_DURABLE\n'

class F01ProjectKeyOriginalSaveTests(unittest.TestCase):
    def test_fixed_local_state_whole_original_readback_and_fsync_is_not_self_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp).resolve();path.chmod(0o700)
            originals=keys._KeyOriginals()
            primary=None
            try:
                parent=originals.directory(path,private=True)
                record=originals.save(parent,'backup.state',RAW)
                self.assertEqual(RAW,os.pread(record['fd'],33,0))
                self.assertEqual(RAW,(path/'backup.state').read_bytes())
                self.assertEqual(0o600,os.fstat(record['fd']).st_mode&0o777)
                self.assertEqual(1,os.fstat(record['fd']).st_nlink)
                originals.verify()
                FACTS.append({'literal_bytes':len(RAW),'literal_sha256':hashlib.sha256(RAW).hexdigest(),
                    'original_readback':True,'native_permission':False})
            finally:
                primary=__import__('sys').exc_info()[1]
                keys._cleanup_key_resources(primary,originals.close())
