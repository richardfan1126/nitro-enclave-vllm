import threading
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import json

from attestation import get_attestation_doc
from encryption import Encryption
from salary import Salary

app = FastAPI()

# Global state
encryption = Encryption()
salary = Salary()
salary_lock = threading.Lock()

class GetAttestationReq(BaseModel):
    nonce: str

class GetAttestationResponse(BaseModel):
    attestation_doc: str

class AddEntryReq(BaseModel):
    public_key: str
    encrypted_payload: str
    encrypted_nonce: str

class AddEntryResponse(BaseModel):
    attestation_doc: str

class GetPositionReq(BaseModel):
    public_key: str
    encrypted_payload: str
    encrypted_nonce: str

class GetPositionResponse(BaseModel):
    attestation_doc: str

@app.get("/health-check")
def health_check():
    return ""

@app.post("/get-attestation", response_model=GetAttestationResponse)
def get_attestation(req: GetAttestationReq):
    nonce = req.nonce.encode()
    public_key = encryption.get_pub_key_bytes()
    user_data = None
    
    attestation_doc = get_attestation_doc(public_key, user_data, nonce)
    if not attestation_doc:
        raise HTTPException(status_code=500, detail="Cannot get attestation document")

    return GetAttestationResponse(attestation_doc=attestation_doc)

@app.post("/add", response_model=AddEntryResponse)
def add_entry(req: AddEntryReq):
    client_pub_key_b64 = req.public_key
    session_key = encryption.get_session_key(client_pub_key_b64)

    encrypted_payload = req.encrypted_payload
    payload = Encryption.decrypt(encrypted_payload, session_key)

    try:
        input_salary = int(payload)
    except ValueError:
        raise HTTPException(status_code=400, detail="Input is not an integer")

    with salary_lock:
        uuid = salary.add(input_salary)

    response = Encryption.encrypt(uuid, session_key)

    encrypted_nonce = req.encrypted_nonce
    nonce = Encryption.decrypt(encrypted_nonce, session_key).encode()

    public_key = None
    user_data = response.encode()

    attestation_doc = get_attestation_doc(public_key, user_data, nonce)
    if not attestation_doc:
        raise HTTPException(status_code=500, detail="Cannot get attestation document")

    return AddEntryResponse(attestation_doc=attestation_doc)

@app.post("/get-position", response_model=GetPositionResponse)
def get_position(req: GetPositionReq):
    client_pub_key_b64 = req.public_key
    session_key = encryption.get_session_key(client_pub_key_b64)

    encrypted_payload = req.encrypted_payload
    uuid = Encryption.decrypt(encrypted_payload, session_key)

    with salary_lock:
        position_and_total = salary.get_position_and_total(uuid)

    if position_and_total:
        response = Encryption.encrypt(json.dumps(position_and_total), session_key)
        user_data = response.encode()
    else:
        user_data = None

    encrypted_nonce = req.encrypted_nonce
    nonce = Encryption.decrypt(encrypted_nonce, session_key).encode()
    
    public_key = None

    attestation_doc = get_attestation_doc(public_key, user_data, nonce)
    if not attestation_doc:
        raise HTTPException(status_code=500, detail="Cannot get attestation document")

    return GetPositionResponse(attestation_doc=attestation_doc)

@app.post("/clear")
def clear_record():
    with salary_lock:
        salary.clear()
    return ""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)