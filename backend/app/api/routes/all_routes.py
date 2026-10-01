import json
from datetime import datetime, timezone
from io import BytesIO
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.database import get_db
from app.dependencies import current_user, require_roles
from app.models import *
from app.schemas.common import *
from app.security.jwt import create_access_token
from app.security.passwords import verify_password
from app.services.audit_service import verify_chain, write_audit
from app.services.evidence_service import evidence_dict, evidence_pdf
from app.services.workflow_service import create_request, decide

router=APIRouter()

def user_json(u):
    return {"id":u.id,"username":u.username,"email":u.email,"full_name":u.full_name,"is_active":u.is_active,"roles":[r.name for r in u.roles]}

def req_json(r):
    return {"id":r.id,"request_number":r.request_number,"artifact_name":r.artifact_name,"artifact_type":r.artifact_type,"artifact_sha256":r.artifact_sha256,"environment":r.environment,"purpose":r.purpose,"status":r.status,"requester":r.requester.full_name,"requester_id":r.requester_id,"key":{"id":r.requested_key.id,"key_id":r.requested_key.key_id,"algorithm":r.requested_key.algorithm},"created_at":r.created_at,"signed_at":r.signed_at,"failure_reason":r.failure_reason}

@router.post("/auth/login")
def login(data:LoginRequest,db:Session=Depends(get_db)):
    u=db.scalar(select(User).where((User.username==data.username)|(User.email==data.username)))
    if not u or not verify_password(data.password,u.password_hash): raise HTTPException(401,"Invalid credentials")
    u.last_login_at=datetime.now(timezone.utc); db.commit()
    return {"access_token":create_access_token(u.id),"token_type":"bearer","user":user_json(u)}

@router.get("/auth/me")
def me(u:User=Depends(current_user)): return user_json(u)

@router.get("/dashboard")
def dashboard(db:Session=Depends(get_db),u:User=Depends(current_user)):
    today=datetime.now(timezone.utc).replace(hour=0,minute=0,second=0,microsecond=0)
    pending=db.scalar(select(func.count()).select_from(SigningRequest).where(SigningRequest.status.in_(["PENDING_SECURITY_APPROVAL","PENDING_RELEASE_APPROVAL"]))) or 0
    signing=db.scalar(select(func.count()).select_from(SigningRequest).where(SigningRequest.status=="SIGNING")) or 0
    completed=db.scalar(select(func.count()).select_from(SigningRequest).where(SigningRequest.signed_at>=today)) or 0
    failed=db.scalar(select(func.count()).select_from(SigningRequest).where(SigningRequest.status=="FAILED")) or 0
    active=db.scalar(select(func.count()).select_from(SigningKey).where(SigningKey.status=="ACTIVE")) or 0
    parts=db.scalars(select(HSMPartition)).all()
    keys=db.scalars(select(SigningKey).order_by(SigningKey.usage_count.desc()).limit(8)).all()
    recent=db.scalars(select(SigningRequest).order_by(SigningRequest.created_at.desc()).limit(8)).all()
    return {"kpis":{"pending_approvals":pending,"signing_in_progress":signing,"completed_today":completed,"failed_operations":failed,"active_keys":active,"hsm_health":{"healthy":sum(p.status=="HEALTHY" for p in parts),"total":len(parts),"label":"Simulated HSM"}},"key_usage":[{"key_id":k.key_id,"usage_count":k.usage_count} for k in keys],"approval_sla":[],"recent_requests":[req_json(r) for r in recent]}

@router.get("/requests")
def requests(status:str|None=None,search:str|None=None,db:Session=Depends(get_db),u:User=Depends(current_user)):
    q=select(SigningRequest).order_by(SigningRequest.created_at.desc())
    if status:q=q.where(SigningRequest.status==status)
    if search:q=q.where(SigningRequest.artifact_name.ilike(f"%{search}%"))
    return [req_json(r) for r in db.scalars(q).all()]

@router.post("/requests",status_code=201)
def new_request(data:RequestCreate,db:Session=Depends(get_db),u:User=Depends(require_roles("DEVELOPER","ADMIN"))):
    if not db.get(SigningKey,data.requested_key_id): raise HTTPException(404,"Requested key not found")
    return req_json(create_request(db,u,data))

@router.get("/requests/{rid}")
def request_detail(rid:int,db:Session=Depends(get_db),u:User=Depends(current_user)):
    r=db.get(SigningRequest,rid)
    if not r: raise HTTPException(404,"Request not found")
    approvals=db.scalars(select(Approval).where(Approval.signing_request_id==rid)).all()
    policies=db.scalars(select(PolicyResult).where(PolicyResult.signing_request_id==rid)).all()
    evidence=db.scalar(select(EvidenceRecord).where(EvidenceRecord.signing_request_id==rid))
    return {**req_json(r),"approvals":[{"type":a.approval_type,"decision":a.decision,"comment":a.comment,"approver":a.approver.full_name,"decided_at":a.decided_at} for a in approvals],"policy_results":[{"rule_type":p.rule_type,"passed":p.passed,"actual":json.loads(p.actual_value),"expected":json.loads(p.expected_value),"message":p.message} for p in policies],"evidence_id":evidence.id if evidence else None}

@router.get("/approvals")
def approvals(db:Session=Depends(get_db),u:User=Depends(current_user)):
    roles={r.name for r in u.roles}; states=[]
    if roles&{"SECURITY_APPROVER","ADMIN"}:states.append("PENDING_SECURITY_APPROVAL")
    if roles&{"RELEASE_MANAGER","ADMIN"}:states.append("PENDING_RELEASE_APPROVAL")
    if not states:return []
    return [req_json(r) for r in db.scalars(select(SigningRequest).where(SigningRequest.status.in_(states),SigningRequest.requester_id!=u.id)).all()]

@router.post("/requests/{rid}/security-approval")
def security(rid:int,data:ApprovalAction,decision:str="APPROVED",db:Session=Depends(get_db),u:User=Depends(current_user)):
    r=db.get(SigningRequest,rid)
    if not r:raise HTTPException(404,"Request not found")
    return req_json(decide(db,r,u,"SECURITY",decision,data.comment))

@router.post("/requests/{rid}/release-approval")
def release(rid:int,data:ApprovalAction,decision:str="APPROVED",db:Session=Depends(get_db),u:User=Depends(current_user)):
    r=db.get(SigningRequest,rid)
    if not r:raise HTTPException(404,"Request not found")
    return req_json(decide(db,r,u,"RELEASE",decision,data.comment))

@router.get("/keys")
def keys(db:Session=Depends(get_db),u:User=Depends(current_user)):
    return [{"id":k.id,"key_id":k.key_id,"display_name":k.display_name,"algorithm":k.algorithm,"environment":k.environment,"status":k.status,"expires_at":k.expires_at,"usage_count":k.usage_count,"hsm_partition":k.hsm_partition.partition_name} for k in db.scalars(select(SigningKey).order_by(SigningKey.key_id)).all()]

@router.get("/hsm")
def hsm(db:Session=Depends(get_db),u:User=Depends(current_user)):
    parts=db.scalars(select(HSMPartition)).all()
    ops=db.scalars(select(HSMOperation).order_by(HSMOperation.started_at.desc()).limit(100)).all()
    return {"provider":"Simulated HSM","production_integration":False,"partitions":[{"id":p.id,"name":p.partition_name,"status":p.status,"slot":p.slot_number,"latency_ms":p.latency_ms,"capacity_percent":p.capacity_percent,"last_health_check":p.last_health_check} for p in parts],"operations":[{"operation_id":o.operation_id,"status":o.status,"latency_ms":o.latency_ms,"algorithm":o.signature_algorithm,"started_at":o.started_at} for o in ops]}

@router.get("/policies")
def policies(db:Session=Depends(get_db),u:User=Depends(current_user)):
    return [{"id":p.id,"name":p.name,"description":p.description,"environment":p.environment,"enabled":p.enabled,"version":p.version,"rules":{r.rule_type:json.loads(r.configuration_json) for r in db.scalars(select(PolicyRule).where(PolicyRule.policy_id==p.id)).all()}} for p in db.scalars(select(Policy)).all()]

@router.get("/audit")
def audit(db:Session=Depends(get_db),u:User=Depends(require_roles("AUDITOR","SECURITY_APPROVER","KEY_CUSTODIAN","ADMIN"))):
    return [{"sequence":a.sequence_number,"timestamp":a.timestamp,"actor_id":a.actor_id,"action":a.action,"resource_type":a.resource_type,"resource_id":a.resource_id,"event":json.loads(a.event_data_json),"previous_hash":a.previous_hash,"entry_hash":a.entry_hash} for a in db.scalars(select(AuditLog).order_by(AuditLog.sequence_number.desc()).limit(500)).all()]

@router.post("/audit/verify")
def verify(db:Session=Depends(get_db),u:User=Depends(require_roles("AUDITOR","SECURITY_APPROVER","KEY_CUSTODIAN","ADMIN"))):
    return verify_chain(db)

@router.get("/evidence")
def evidence(db:Session=Depends(get_db),u:User=Depends(current_user)):
    return [evidence_dict(e)|{"id":e.id} for e in db.scalars(select(EvidenceRecord).order_by(EvidenceRecord.evidence_created_at.desc())).all()]

@router.get("/evidence/{eid}/export/json")
def export_json(eid:int,db:Session=Depends(get_db),u:User=Depends(current_user)):
    e=db.get(EvidenceRecord,eid)
    if not e:raise HTTPException(404,"Evidence not found")
    return Response(json.dumps(evidence_dict(e),indent=2),media_type="application/json")

@router.get("/evidence/{eid}/export/pdf")
def export_pdf(eid:int,db:Session=Depends(get_db),u:User=Depends(current_user)):
    e=db.get(EvidenceRecord,eid)
    if not e:raise HTTPException(404,"Evidence not found")
    return StreamingResponse(BytesIO(evidence_pdf(e)),media_type="application/pdf")

@router.get("/monitoring")
def monitoring(db:Session=Depends(get_db),u:User=Depends(current_user)):
    ops=db.scalars(select(HSMOperation)).all(); total=len(ops); success=sum(o.status=="SUCCESS" for o in ops)
    pending=db.scalar(select(func.count()).select_from(SigningRequest).where(SigningRequest.status.in_(["PENDING_SECURITY_APPROVAL","PENDING_RELEASE_APPROVAL"]))) or 0
    return {"success_rate":round(success*100/total,2) if total else 100,"average_latency_ms":round(sum(o.latency_ms for o in ops)/total,1) if total else 0,"queue_depth":pending,"operations":[{"time":o.started_at,"status":o.status,"latency_ms":o.latency_ms} for o in ops[-50:]]}

@router.get("/users")
def users(db:Session=Depends(get_db),u:User=Depends(require_roles("ADMIN"))):
    return [user_json(x) for x in db.scalars(select(User).order_by(User.username)).all()]

@router.get("/settings")
def settings(db:Session=Depends(get_db),u:User=Depends(current_user)):
    return {s.setting_key:json.loads(s.setting_value_json) for s in db.scalars(select(SystemSetting)).all()}
