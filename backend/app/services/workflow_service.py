from datetime import datetime, timezone
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from fastapi import HTTPException
from app.models import Approval, SigningRequest, User
from app.services.audit_service import write_audit
from app.services.evidence_service import create_evidence
from app.services.policy_engine import artifact_type, evaluate, required_approvals
from app.services.simulated_hsm import sign

def create_request(db:Session,user:User,data)->SigningRequest:
    n=(db.scalar(select(func.count()).select_from(SigningRequest)) or 0)+1001
    req=SigningRequest(request_number=f"SR-{n}",requester_id=user.id,artifact_name=data.artifact_name,artifact_type=artifact_type(data.artifact_name),artifact_sha256=data.artifact_sha256,environment=data.environment.upper(),purpose=data.purpose,requested_key_id=data.requested_key_id,status="CREATED")
    db.add(req); db.flush(); write_audit(db,user.id,"REQUEST_CREATED","SIGNING_REQUEST",req.request_number,{"artifact":req.artifact_name,"environment":req.environment})
    ok,_=evaluate(db,req,user); req.policy_validated_at=datetime.now(timezone.utc)
    if not ok:
        req.status="FAILED"; req.failed_at=datetime.now(timezone.utc); req.failure_reason="Policy validation failed"; write_audit(db,user.id,"POLICY_VALIDATION_FAILED","SIGNING_REQUEST",req.request_number,{})
    else:
        req.status="PENDING_SECURITY_APPROVAL"; write_audit(db,user.id,"POLICY_VALIDATED","SIGNING_REQUEST",req.request_number,{"status":req.status})
    db.commit(); db.refresh(req); return req

def decide(db:Session,req:SigningRequest,user:User,approval_type:str,decision:str,comment:str)->SigningRequest:
    if req.requester_id==user.id: raise HTTPException(403,"Separation of duties: requester cannot approve their own request")
    expected="PENDING_SECURITY_APPROVAL" if approval_type=="SECURITY" else "PENDING_RELEASE_APPROVAL"
    if req.status!=expected: raise HTTPException(409,f"Request is {req.status}; expected {expected}")
    role="SECURITY_APPROVER" if approval_type=="SECURITY" else "RELEASE_MANAGER"
    if role not in {r.name for r in user.roles} and "ADMIN" not in {r.name for r in user.roles}: raise HTTPException(403,f"{role} role required")
    ap=Approval(signing_request_id=req.id,approval_type=approval_type,approver_id=user.id,decision=decision,comment=comment); db.add(ap)
    write_audit(db,user.id,f"{approval_type}_{decision}","SIGNING_REQUEST",req.request_number,{"comment":comment})
    if decision=="REJECTED": req.status="REJECTED"; req.rejected_at=datetime.now(timezone.utc); db.commit(); return req
    needed=required_approvals(db,req.environment)
    if approval_type=="SECURITY" and "RELEASE" in needed: req.status="PENDING_RELEASE_APPROVAL"
    else: _complete(db,req,user.id)
    db.commit(); db.refresh(req); return req

def _complete(db:Session,req:SigningRequest,actor_id:int)->None:
    req.status="APPROVED"; req.approved_at=datetime.now(timezone.utc); write_audit(db,actor_id,"REQUEST_APPROVED","SIGNING_REQUEST",req.request_number,{})
    req.status="SIGNING"; req.signing_started_at=datetime.now(timezone.utc); write_audit(db,actor_id,"SIGNING_STARTED","SIGNING_REQUEST",req.request_number,{"provider":"SIMULATED_HSM"})
    try:
        op,sig=sign(db,req); req.status="SIGNED"; req.signed_at=datetime.now(timezone.utc); write_audit(db,actor_id,"SIMULATED_SIGNING_COMPLETED","SIGNING_REQUEST",req.request_number,{"operation_id":op.operation_id}); ev=create_evidence(db,req,op.operation_id,sig); write_audit(db,actor_id,"EVIDENCE_GENERATED","EVIDENCE",ev.evidence_id,{"evidence_sha256":ev.evidence_sha256})
    except Exception as exc:
        req.status="FAILED"; req.failed_at=datetime.now(timezone.utc); req.failure_reason=str(exc); write_audit(db,actor_id,"SIGNING_FAILED","SIGNING_REQUEST",req.request_number,{"error":str(exc)}); raise
