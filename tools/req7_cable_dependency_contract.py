"""Separate CableTracker-style SDK source contract; no SDK import or send.

This contract is not old C14, installation, binary execution, SDK behavior,
credential/source qualification or dispatch authority. Transport fields are
required construction policy, not evidence of actual runtime behavior.
"""
from dataclasses import dataclass
from importlib import metadata
import hashlib
import json
import re
import sys

from tools.req7_dependency_contract import _read as _original_source_read

POLICY_PATH = "infra/docker/req7-cable-dependency-policy.json"
LOCK_PATH = "infra/docker/requirements-req7-cable-sync.txt"
PINS = (("certifi","2026.7.22"),("cffi","2.0.0"),("charset-normalizer","3.5.1"),("cryptography","50.0.1"),("google-api-core","2.30.3"),("google-api-python-client","2.198.0"),("google-auth-httplib2","0.3.1"),("google-auth","2.50.0"),("googleapis-common-protos","1.75.0"),("httplib2","0.32.0"),("idna","3.19"),("proto-plus","1.27.2"),("protobuf","6.33.6"),("pyasn1-modules","0.4.2"),("pyasn1","0.6.4"),("pycparser","2.23"),("pyparsing","3.3.2"),("requests","2.32.5"),("uritemplate","4.2.0"),("urllib3","2.6.3"))
ARTIFACTS = (("certifi","any","certifi-2026.7.22-py3-none-any.whl","62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775"),("cffi","aarch64","cffi-2.0.0-cp312-cp312-manylinux2014_aarch64.manylinux_2_17_aarch64.whl","b21e08af67b8a103c71a250401c78d5e0893beff75e28c53c98f4de42f774062"),("cffi","x86_64","cffi-2.0.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl","3e17ed538242334bf70832644a32a7aae3d83b57567f9fd60a26257e992b79ba"),("charset-normalizer","any","charset_normalizer-3.5.1-py3-none-any.whl","6df0ec430f9a831772c23ca5a224cba36517a58a84bb32c32bb59a9fa67c47f6"),("cryptography","aarch64","cryptography-50.0.1-cp39-abi3-manylinux_2_28_aarch64.whl","4c4188f7c0cf655be5c06342b817ed0f9595b69ffa2b12026e5353eed29dea88"),("cryptography","x86_64","cryptography-50.0.1-cp39-abi3-manylinux_2_28_x86_64.whl","407fe2b6db00939c05c0e945e9914238f2f0a430974839429dafc82b1ee6bee5"),("google-api-core","any","google_api_core-2.30.3-py3-none-any.whl","a85761ba72c444dad5d611c2220633480b2b6be2521eca69cca2dbb3ffd6bfe8"),("google-api-python-client","any","google_api_python_client-2.198.0-py3-none-any.whl","fabac935474e817da5e662ff61bf7139439d6f92b32d332a7318a2d45931e03e"),("google-auth-httplib2","any","google_auth_httplib2-0.3.1-py3-none-any.whl","682356a90ef4ba3d06548c37e9112eea6fc00395a11b0303a644c1a86abc275c"),("google-auth","any","google_auth-2.50.0-py3-none-any.whl","04382175e28b94f49694977f0a792688b59a668def1499e9d8de996dc9ce5b15"),("googleapis-common-protos","any","googleapis_common_protos-1.75.0-py3-none-any.whl","961ed60399c457ceb0ee8f285a84c870aabc9c6a832b9d37bb281b5bebde43ed"),("httplib2","any","httplib2-0.32.0-py3-none-any.whl","dc6705cacdf3fb0a2aba7629fa33c90fd93e30035db0c157325826be177e4816"),("idna","any","idna-3.19-py3-none-any.whl","815e7be7a7806d54abb586dc943addc79e8b2ee16915059658cbeff4b1b43bf4"),("proto-plus","any","proto_plus-1.27.2-py3-none-any.whl","6432f75893d3b9e70b9c412f1d2f03f65b11fb164b793d14ae2ca01821d22718"),("protobuf","any","protobuf-6.33.6-py3-none-any.whl","77179e006c476e69bf8e8ce866640091ec42e1beb80b213c3900006ecfba6901"),("pyasn1-modules","any","pyasn1_modules-0.4.2-py3-none-any.whl","29253a9207ce32b64c3ac6600edc75368f98473906e8fd1043bd6b5b1de2c14a"),("pyasn1","any","pyasn1-0.6.4-py3-none-any.whl","deda9277cfd454080ec40b207fb6df82206a3a2688735233cdcd8d3d565f088b"),("pycparser","any","pycparser-2.23-py3-none-any.whl","e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934"),("pyparsing","any","pyparsing-3.3.2-py3-none-any.whl","850ba148bd908d7e2411587e247a1e4f0327839c40e2e5e6d05a007ecc69911d"),("requests","any","requests-2.32.5-py3-none-any.whl","2462f94637a34fd532264295e186976db0f5d453d1cdd31473c85a6a161affb6"),("uritemplate","any","uritemplate-4.2.0-py3-none-any.whl","962201ba1c4edcab02e60f9a0d3821e82dfc5d2d6662a21abd533879bdb8a686"),("urllib3","any","urllib3-2.6.3-py3-none-any.whl","bf272323e553dfb2e87d9bfd225ca7b0f467b919d7bbd355436d3fd37cb0acd4"))
_HEADER = "# REQ7 Cable sync SDK v1: CPython 3.12 Linux aarch64/x86_64; wheels only; no extras; pip --no-deps --require-hashes."
_KEYS = {"schema_version","contract","python","platform","architectures","extras",
         "distributions","artifacts","development_conditional","transport"}
_TRANSPORT = {"sdk":"google-api-python-client","http":"google-auth-httplib2",
              "discovery":"static-only","api_retries":0,"authentication_response_replays":0}

class CableDependencyContractError(ValueError):
    def __init__(self): super().__init__("invalid_req7_cable_dependency_contract")

@dataclass(frozen=True)
class CableDependencyContract:
    policy_sha256: str
    lock_sha256: str
    distributions: tuple
    artifacts: tuple

@dataclass(frozen=True)
class CableDependencyIdentity:
    policy_sha256: str
    lock_sha256: str
    versions: tuple

def _pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise CableDependencyContractError()
        result[key]=value
    return result

def _constant(_):raise CableDependencyContractError()

def _lock_bytes():
    lines=[_HEADER]
    for name,version in PINS:
        selected=[record for record in ARTIFACTS if record[0]==name]
        lines.extend("# wheel: "+f+" sha256:"+h for _,_,f,h in selected)
        lines.append(name+"=="+version+" "+chr(92))
        hashes=sorted(record[3] for record in selected)
        lines.extend("    --hash=sha256:"+h+(" "+chr(92) if i<len(hashes)-1 else "")
                     for i,h in enumerate(hashes))
    return ("\n".join(lines)+"\n").encode("ascii")

def load_cable_dependency_contract(root):
    """Read the fixed reviewed pair through original no-follow bounded FDs.

    Reobserve original bytes AND full file identities across the pair. A
    same-byte name replacement is stale, never adoption of a new authority.
    Exact reviewed public artifacts are fixed here, not arbitrary new hashes.
    """
    try:
        policy_read=_original_source_read(root,POLICY_PATH)
        lock_read=_original_source_read(root,LOCK_PATH)
        if (policy_read!=_original_source_read(root,POLICY_PATH)
                or lock_read!=_original_source_read(root,LOCK_PATH)):
            raise CableDependencyContractError()
        raw,_=policy_read;lock,_=lock_read
        value=json.loads(raw.decode("ascii"),object_pairs_hook=_pairs,parse_constant=_constant)
        canonical=(json.dumps(value,sort_keys=True,ensure_ascii=True,indent=2,allow_nan=False)+"\n").encode("ascii")
        if (type(value) is not dict or set(value)!=_KEYS or raw!=canonical
                or type(value["schema_version"]) is not int or value["schema_version"]!=1
                or value["contract"]!="REQ7-CABLE-SDK-V1" or value["python"]!="CPython-3.12"
                or value["platform"]!="linux" or value["architectures"]!=["aarch64","x86_64"]
                or value["extras"]!=[]
                or value["distributions"]!=[{"name":n,"version":v} for n,v in PINS]
                or value["artifacts"]!=[{"name":n,"architecture":a,"filename":f,"sha256":h} for n,a,f,h in ARTIFACTS]
                or value["development_conditional"]!={"name":"typing_extensions","version":"4.16.0",
                                                     "marker":"python_full_version < '3.11'"}
                or value["transport"]!=_TRANSPORT):
            raise CableDependencyContractError()
        if any(type(value["transport"][key]) is not int
               for key in ("api_retries","authentication_response_replays")):
            raise CableDependencyContractError()
        if lock!=_lock_bytes():raise CableDependencyContractError()
        return CableDependencyContract(hashlib.sha256(raw).hexdigest(),
            hashlib.sha256(lock).hexdigest(),PINS,ARTIFACTS)
    except Exception:
        raise CableDependencyContractError() from None

def _contract(contract):
    if (type(contract) is not CableDependencyContract
            or contract.distributions!=PINS or contract.artifacts!=ARTIFACTS
            or any(type(value) is not str or re.fullmatch(r"[0-9a-f]{64}",value) is None
                   for value in (contract.policy_sha256,contract.lock_sha256))):
        raise CableDependencyContractError()

def cable_architecture_artifacts(contract,architecture):
    _contract(contract)
    if type(architecture) is not str or architecture not in ("aarch64","x86_64"):
        raise CableDependencyContractError()
    return tuple((n,f,h) for n,a,f,h in contract.artifacts if a in ("any",architecture))

def installed_cable_dependency_identity(contract,*,python_version=None,version_getter=None):
    """Metadata-only observation. A caller-built DTO is never permission.

    The native image/factory still owes managed-venv file origin, complete
    source identity, credential/target/source ownership and actual transport
    supervision/cleanup before SDK construction or any network operation.
    """
    _contract(contract)
    py=sys.version_info[:2] if python_version is None else python_version
    if (type(py) is not tuple or len(py)!=2 or any(type(v) is not int for v in py)
            or py[0]!=3 or py[1]<9):
        raise CableDependencyContractError()
    getter=(lambda name:metadata.distribution(name).version) if version_getter is None else version_getter
    versions=PINS+((("typing_extensions","4.16.0"),) if py<(3,11) else ())
    try:
        for name,version in versions:
            if getter(name)!=version:raise CableDependencyContractError()
    except Exception:
        raise CableDependencyContractError() from None
    return CableDependencyIdentity(contract.policy_sha256,contract.lock_sha256,versions)
