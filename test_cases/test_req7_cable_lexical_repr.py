"""Independent repr-only DATA UNIT. Literal marker, no credential or authority."""
import importlib.machinery,importlib.util,os,sys,unittest
from pathlib import Path

class LexicalReprTests(unittest.TestCase):
    def test_internal_credential_bytes_never_appear_in_default_record_or_container_repr(self):
        source=Path(__file__).resolve().parents[1]/'monitor/issue_tracker_publish_runtime.py'
        name='req7_private_lexical_repr_unit_candidate'
        loader=importlib.machinery.SourceFileLoader(name,str(source))
        spec=importlib.util.spec_from_loader(name,loader);module=importlib.util.module_from_spec(spec)
        sys.modules[name]=module
        try:
            loader.exec_module(module)
            # Deliberately NOT qualified input, owner, token, SDK key or factory.
            marker=b'REQ7-OWNED-REPR-SECRET-MARKER-NOT-A-CREDENTIAL'
            record=module._CableSourceLexical(object(),object(),(),object(),
                object(),object(),marker,lambda:None,(123,456))
            for label,text in (('repr',repr(record)),('str',str(record)),
                               ('container',repr([record]))):
                with self.subTest(view=label):
                    self.assertNotIn(marker.decode('ascii'),text,
                                     'PRIVATE_LEXICAL_RECORD_DEFAULT_REPR_EXPOSES_CREDENTIAL_BYTES')
        finally:sys.modules.pop(name,None)
