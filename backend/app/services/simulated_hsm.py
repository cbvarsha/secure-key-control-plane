import hashlib, secrets
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models import HSMOperation, SigningRequest

def sign(db:Session, req:SigningRequest)->tuple[HSMOperation,str]:
    key=req.requested_key; partition=key.hsm_partition
    if partition.status!="HEALTHY": raise RuntimeError("Simulated HSM partition is not healthy")
    started=datetime.now(timezone.utc); latency=max(5, partition.latency_ms + secrets.randbelow(20)); op_id=f"SIM-HSM-{secrets.token_hex(6).upper()}"
    simulated="SIMULATED-"+hashlib.sha256(f"{op_id}|{key.key_id}|{req.artifact_sha256}".encode()).hexdigest()
    op=HSMOperation(operation_id=op_id,partition_id=partition.id,key_id=key.id,signing_request_id=req.id,status="SUCCESS",latency_ms=latency,signature_algorithm=key.algorithm,artifact_sha256=req.artifact_sha256,started_at=started,completed_at=datetime.now(timezone.utc)); db.add(op); key.usage_count+=1; db.flush(); return op,simulated
