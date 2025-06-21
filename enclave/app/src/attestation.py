import base64
import subprocess
import sys
from typing import List, Optional

def _error_exit(msg: str, code: int, nsm_fd: int):
    print(msg, file=sys.stderr)
    sys.exit(code)

def _nsm_cli_attest(input: List[str]) -> str:
    """
    Obtain Nitro Enclave attestation document via nsm-cli
    """
    cmd = ["nsm-cli", "attest"]

    if "public-key-b64" in input:
        cmd += ["--public-key-b64", input["public-key-b64"]]

    if "user-data-b64" in input:
        cmd += ["--user-data-b64", input["user-data-b64"]]

    if "nonce-b64" in input:
        cmd += ["--nonce-b64", input["nonce-b64"]]

    # Call the standalone nsm-cli through subprocess
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)

    attestation_doc_b64 = proc.communicate()[0]

    # Return the base64-encoded attestation document
    return attestation_doc_b64.decode()

def get_attestation_doc(public_key: Optional[bytes], user_data: Optional[bytes], nonce: Optional[bytes]) -> Optional[str]:
    """
    Get attestation document from nsm-cli
    """

    try:
        nsm_cli_args = {}

        if public_key:
            public_key_b64 = base64.b64encode(public_key).decode()
            nsm_cli_args["public-key-b64"] = public_key_b64

        if user_data:
            user_data_b64 = base64.b64encode(user_data).decode()
            nsm_cli_args["user-data-b64"] = user_data_b64

        if nonce:
            nonce_b64 = base64.b64encode(nonce).decode()
            nsm_cli_args["nonce-b64"] = nonce_b64

        attestation_doc_b64 = _nsm_cli_attest(nsm_cli_args)
        return attestation_doc_b64

    except Exception as e:
        _error_exit(f"Attestation error: {str(e)}", -1, 0)
        return None
