# /// script
# requires-python = ">=3.11"
# dependencies = ["fastapi", "uvicorn"]
# ///
"""Minimal Step 0 enrollment test server for ESP32 Root of Trust demo."""

import base64
import os
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="RoT Step 0 Test Server")

devices: dict[str, dict] = {}

KYBER768_PK_SIZE = 1184


class EnrollRequest(BaseModel):
    Step: int
    Device_Name: str
    Mac_Address: str
    PUF_Hash: str


class HeartbeatRequest(BaseModel):
    device_id: str
    status: str = "alive"


@app.post("/api/v1/enroll")
async def enroll(req: EnrollRequest):
    if req.Step != 0:
        raise HTTPException(400, f"Only Step 0 supported, got Step {req.Step}")

    mac_bytes = base64.b64decode(req.Mac_Address)
    mac_hex = mac_bytes.hex(":")

    dummy_pk = os.urandom(KYBER768_PK_SIZE)
    pk_b64 = base64.b64encode(dummy_pk).decode()

    devices[req.Device_Name] = {
        "mac": mac_hex,
        "puf_hash_b64": req.PUF_Hash,
        "kyber_pk_b64": pk_b64,
        "enrolled_at": datetime.now(timezone.utc).isoformat(),
    }

    print(f"[ENROLL] {req.Device_Name} (MAC: {mac_hex})")

    return {
        "Step": 0,
        "Server_Name": "test-enrollment-server",
        "kyber_pk": pk_b64,
    }


@app.post("/api/v1/device/heartbeat")
async def heartbeat(req: HeartbeatRequest):
    print(f"[HEARTBEAT] {req.device_id} - {req.status}")
    return {"status": "ok", "device_id": req.device_id}


@app.get("/api/v1/devices")
async def list_devices():
    return {"count": len(devices), "devices": devices}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
