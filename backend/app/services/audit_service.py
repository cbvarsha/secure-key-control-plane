import hashlib, json
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models import AuditLog

def canonical(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)

def digest(seq:int, ts:datetime, actor:int|None, action:str, rtype:str, rid:str, data:str, prev:str)->str:
    ts_norm = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    raw=f"{seq}|{ts_norm.astimezone(timezone.utc).isoformat()}|{actor}|{action}|{rtype}|{rid}|{data}|{prev}".encode()
    return hashlib.sha256(raw).hexdigest()

def write_audit(db:Session, actor_id:int|None, action:str, resource_type:str, resource_id:str, event:dict)->AuditLog:
    last=db.scalar(select(AuditLog).order_by(AuditLog.sequence_number.desc()).limit(1))
    seq=(last.sequence_number+1) if last else 1
    prev=last.entry_hash if last else "0"*64
    ts=datetime.now(timezone.utc)
    data=canonical(event)
    h=digest(seq,ts,actor_id,action,resource_type,resource_id,data,prev)
    row=AuditLog(sequence_number=seq,timestamp=ts,actor_id=actor_id,action=action,resource_type=resource_type,resource_id=str(resource_id),event_data_json=data,previous_hash=prev,entry_hash=h)
    db.add(row); db.flush()
    return row

def verify_chain(db:Session)->dict:
    rows=db.scalars(select(AuditLog).order_by(AuditLog.sequence_number)).all()
    prev="0"*64
    for row in rows:
        expected=digest(row.sequence_number,row.timestamp,row.actor_id,row.action,row.resource_type,row.resource_id,row.event_data_json,prev)
        if row.previous_hash!=prev or row.entry_hash!=expected:
            return {"valid":False,"checked":row.sequence_number-1,"broken_at":row.sequence_number}
        prev=row.entry_hash
    return {"valid":True,"checked":len(rows),"broken_at":None}
