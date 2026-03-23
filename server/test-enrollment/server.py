# /// script
# requires-python = ">=3.11"
# dependencies = ["fastapi", "uvicorn"]
# ///
"""Minimal test server for ESP32 Root of Trust enrollment and events."""

import base64
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="RoT Test Server")

devices: dict[str, dict] = {}
events: list[dict] = []

KYBER768_PK_SIZE = 1184


class EnrollRequest(BaseModel):
    Step: int
    Device_Name: str
    Mac_Address: str
    PUF_Hash: str


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
async def heartbeat(body: dict):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    device_id = body.get("device_id", "unknown")
    msg_type = body.get("type", "heartbeat")
    trigger = body.get("trigger", "")

    if msg_type == "event":
        events.append({"device_id": device_id, "trigger": trigger, "ts": ts})
        print(f"[EVENT]     {device_id} trigger={trigger} ({ts})")
    else:
        print(f"[HEARTBEAT] {device_id} ({ts})")

    return {"status": "ok", "device_id": device_id}


@app.get("/api/v1/devices")
async def list_devices():
    return {"count": len(devices), "devices": devices}


@app.get("/api/v1/events")
async def list_events():
    return {"count": len(events), "events": events[-50:]}


# Servir web flasher si el directorio existe
flasher_dir = Path(__file__).resolve().parent / "../../web/puf-web-flasher"
if flasher_dir.exists():
    app.mount("/flasher", StaticFiles(directory=str(flasher_dir.resolve()), html=True))
    print(f"[FLASHER] Web flasher disponible en http://localhost:8000/flasher/")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
