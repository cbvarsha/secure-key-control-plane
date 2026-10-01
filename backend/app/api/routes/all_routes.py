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
def user_json(u): return {"id":u.id,"username":u.username,"email":u.email,"full_name":u.full_name,"is_active":u.is_active,"roles":[r.name for r in u.roles]}
def req_json(r): return {"id":r.id,"request_number":r.request_number,"artifact_name":r.artifact_name,"artifact_type":r.artifact_type,"artifact_sha256":r.artifact_sha256,"environment":r.environment,"purpose":r.purpose,"status":r.status,"requester":r.requester.full_name,"requester_id":r.requester_id,"key":{"id":r.requested_key.id,"key_id":r.requested_key.key_id,"algorithm":r.requested_key.algorithm},"created_at":r.created_at,"signed_at":r.signed_at,"failure_reason":r.failure_reason}

@router.post('/auth/login')
def login(data:LoginRequest,db:Session=Depends(get_db)):
    u=db.scalar(select(User).where((User.username==data.username)|(User.email==data.username)))
    if not u or not verify_password(data.password,u.password_hash): raise HTTPException(401,'Invalid credentials')
    u.last_login_at=datetime.now(timezone.utc); db.commit(); return {"access_token":create_access_token(u.id),"token_type":"bearer","user":user_json(u)}
@router.get('/auth/me')
def me(u:User=Depends(current_user)): return user_json(u)

@router.get('/dashboard')
def dashboard(db:Session=Depends(get_db),u:User=Depends(current_user)):
    today=datetime.now(timezone.utc).replace(hour=0,minute=0,second=0,microsecond=0)
    pending=db.scalar(select(func.count()).select_from(SigningRequest).where(SigningRequest.status.in_(['PENDING_SECURITY_APPROVAL','PENDING_RELEASE_APPROVAL']))) or 0
    signing=db.scalar(select(func.count()).select_from(SigningRequest).where(SigningRequest.status=='SIGNING')) or 0
    completed=db.scalar(select(func.count()).select_from(SigningRequest).where(SigningRequest.signed_at>=today)) or 0
    failed=db.scalar(select(func.count()).select_from(SigningRequest).where(SigningRequest.status=='FAILED')) or 0
    active=db.scalar(select(func.count()).select_from(SigningKey).where(SigningKey.status=='ACTIVE')) or 0
    parts=db.scalars(select(HSMPartition)).all(); hsm={"healthy":sum(p.status=='HEALTHY' for p in parts),"total":len(parts),"label":"Simulated HSM"}
    keys=db.scalars(select(SigningKey).order_by(SigningKey.usage_count.desc()).limit(8)).all(); recent=db.scalars(select(SigningRequest).order_by(SigningRequest.created_at.desc()).limit(8)).all()
    sla={"<1h":0,"1-2h":0,"2-4h":0,">4h":0}
    for a in db.scalars(select(Approval).where(Approval.decided_at.is_not(None))).all():
        req=db.get(SigningRequest,a.signing_request_id)
        if not req or not a.decided_at: continue
        hours=max(0,(a.decided_at.replace(tzinfo=timezone.utc) if a.decided_at.tzinfo is None else a.decided_at)-(req.created_at.replace(tzinfo=timezone.utc) if req.created_at.tzinfo is None else req.created_at)).total_seconds()/3600
        sla["<1h" if hours<1 else "1-2h" if hours<2 else "2-4h" if hours<4 else ">4h"]+=1
    return {"kpis":{"pending_approvals":pending,"signing_in_progress":signing,"completed_today":completed,"failed_operations":failed,"active_keys":active,"hsm_health":hsm},"key_usage":[{"key_id":k.key_id,"usage_count":k.usage_count} for k in keys],"approval_sla":[{"bucket":b,"count":c} for b,c in sla.items()],"recent_requests":[req_json(r) for r in recent]}

@router.get('/requests')
def requests(status:str|None=None,search:str|None=None,db:Session=Depends(get_db),u:User=Depends(current_user)):
    q=select(SigningRequest).order_by(SigningRequest.created_at.desc())
    if status: q=q.where(SigningRequest.status==status)
    if search: q=q.where(SigningRequest.artifact_name.ilike(f'%{search}%'))
    return [req_json(r) for r in db.scalars(q).all()]
@router.post('/requests',status_code=201)
def new_request(data:RequestCreate,db:Session=Depends(get_db),u:User=Depends(require_roles('DEVELOPER','ADMIN'))):
    if not db.get(SigningKey,data.requested_key_id): raise HTTPException(404,'Requested key not found')
    return req_json(create_request(db,u,data))
@router.get('/requests/{rid}')
def request_detail(rid:int,db:Session=Depends(get_db),u:User=Depends(current_user)):
    r=db.get(SigningRequest,rid)
    if not r: raise HTTPException(404,'Request not found')
    approvals=db.scalars(select(Approval).where(Approval.signing_request_id==rid)).all(); policies=db.scalars(select(PolicyResult).where(PolicyResult.signing_request_id==rid)).all(); evidence=db.scalar(select(EvidenceRecord).where(EvidenceRecord.signing_request_id==rid))
    return {**req_json(r),"approvals":[{"type":a.approval_type,"decision":a.decision,"comment":a.comment,"approver":a.approver.full_name,"decided_at":a.decided_at} for a in approvals],"policy_results":[{"rule_type":p.rule_type,"passed":p.passed,"actual":json.loads(p.actual_value),"expected":json.loads(p.expected_value),"message":p.message} for p in policies],"evidence_id":evidence.id if evidence else None}

@router.get('/approvals')
def approvals(db:Session=Depends(get_db),u:User=Depends(current_user)):
    roles={r.name for r in u.roles}; states=[]
    if roles&{'SECURITY_APPROVER','ADMIN'}: states.append('PENDING_SECURITY_APPROVAL')
    if roles&{'RELEASE_MANAGER','ADMIN'}: states.append('PENDING_RELEASE_APPROVAL')
    if not states:return []
    rows=db.scalars(select(SigningRequest).where(SigningRequest.status.in_(states),SigningRequest.requester_id!=u.id).order_by(SigningRequest.created_at)).all(); return [req_json(r) for r in rows]
@router.post('/requests/{rid}/security-approval')
def security(rid:int,data:ApprovalAction,decision:str='APPROVED',db:Session=Depends(get_db),u:User=Depends(current_user)):
    r=db.get(SigningRequest,rid)
    if not r: raise HTTPException(404,'Request not found')
    if decision not in {'APPROVED','REJECTED'}: raise HTTPException(422,'Invalid decision')
    return req_json(decide(db,r,u,'SECURITY',decision,data.comment))
@router.post('/requests/{rid}/release-approval')
def release(rid:int,data:ApprovalAction,decision:str='APPROVED',db:Session=Depends(get_db),u:User=Depends(current_user)):
    r=db.get(SigningRequest,rid)
    if not r: raise HTTPException(404,'Request not found')
    if decision not in {'APPROVED','REJECTED'}: raise HTTPException(422,'Invalid decision')
    return req_json(decide(db,r,u,'RELEASE',decision,data.comment))

@router.get('/keys')
def keys(db:Session=Depends(get_db),u:User=Depends(current_user)):
    return [{"id":k.id,"key_id":k.key_id,"display_name":k.display_name,"algorithm":k.algorithm,"environment":k.environment,"status":k.status,"expires_at":k.expires_at,"usage_count":k.usage_count,"hsm_partition":k.hsm_partition.partition_name} for k in db.scalars(select(SigningKey).order_by(SigningKey.key_id)).all()]
@router.get('/keys/{kid}')
def key_detail(kid:int,db:Session=Depends(get_db),u:User=Depends(current_user)):
    k=db.get(SigningKey,kid)
    if not k: raise HTTPException(404,'Key not found')
    events=db.scalars(select(KeyLifecycleEvent).where(KeyLifecycleEvent.key_id==kid).order_by(KeyLifecycleEvent.created_at.desc())).all()
    return {"id":k.id,"key_id":k.key_id,"display_name":k.display_name,"algorithm":k.algorithm,"environment":k.environment,"status":k.status,"expires_at":k.expires_at,"certificate_subject":k.certificate_subject,"certificate_serial":k.certificate_serial,"usage_count":k.usage_count,"events":[{"action":e.action,"reason":e.reason,"previous_status":e.previous_status,"new_status":e.new_status,"created_at":e.created_at} for e in events]}
@router.post('/keys/{kid}/lifecycle')
def lifecycle(kid:int,data:KeyLifecycleAction,db:Session=Depends(get_db),u:User=Depends(require_roles('KEY_CUSTODIAN','ADMIN'))):
    k=db.get(SigningKey,kid)
    if not k: raise HTTPException(404,'Key not found')
    mapping={'ACTIVATE':'ACTIVE','SUSPEND':'SUSPENDED','ROTATE':'ROTATING','RETIRE':'RETIRED'}; action=data.action.upper()
    if action not in mapping: raise HTTPException(422,'Invalid lifecycle action')
    old=k.status;k.status=mapping[action]; db.add(KeyLifecycleEvent(key_id=k.id,action=action,previous_status=old,new_status=k.status,performed_by=u.id,reason=data.reason)); write_audit(db,u.id,f'KEY_{action}','SIGNING_KEY',k.key_id,{"from":old,"to":k.status,"reason":data.reason});db.commit();return {"key_id":k.key_id,"status":k.status}

@router.get('/hsm')
def hsm(db:Session=Depends(get_db),u:User=Depends(current_user)):
    parts=db.scalars(select(HSMPartition)).all(); ops=db.scalars(select(HSMOperation).order_by(HSMOperation.started_at.desc()).limit(100)).all();return {"provider":"Simulated HSM","production_integration":False,"partitions":[{"id":p.id,"name":p.partition_name,"status":p.status,"slot":p.slot_number,"latency_ms":p.latency_ms,"capacity_percent":p.capacity_percent,"last_health_check":p.last_health_check} for p in parts],"operations":[{"operation_id":o.operation_id,"status":o.status,"latency_ms":o.latency_ms,"algorithm":o.signature_algorithm,"started_at":o.started_at} for o in ops]}

@router.get('/policies')
def policies(db:Session=Depends(get_db),u:User=Depends(current_user)):
    out=[]
    for p in db.scalars(select(Policy)).all(): out.append({"id":p.id,"name":p.name,"description":p.description,"environment":p.environment,"enabled":p.enabled,"version":p.version,"rules":{r.rule_type:json.loads(r.configuration_json) for r in db.scalars(select(PolicyRule).where(PolicyRule.policy_id==p.id)).all()}})
    return out
@router.put('/policies/{pid}')
def update_policy(pid:int,data:PolicyUpdate,db:Session=Depends(get_db),u:User=Depends(require_roles('SECURITY_APPROVER','ADMIN'))):
    p=db.get(Policy,pid)
    if not p:raise HTTPException(404,'Policy not found')
    vals={'ALLOWED_ALGORITHMS':data.allowed_algorithms,'ALLOWED_ARTIFACT_TYPES':[x.upper() for x in data.allowed_artifact_types],'REQUIRED_APPROVALS':[x.upper() for x in data.required_approvals]}
    for typ,val in vals.items():
        r=db.scalar(select(PolicyRule).where(PolicyRule.policy_id==pid,PolicyRule.rule_type==typ))
        if r:r.configuration_json=json.dumps(val)
        else:db.add(PolicyRule(policy_id=pid,rule_type=typ,configuration_json=json.dumps(val))
    p.version+=1;write_audit(db,u.id,'POLICY_UPDATED','POLICY',str(pid),{"version":p.version});db.commit();return {"id":p.id,"version":p.version}

@router.get('/audit')
def audit(search:str|None=None,db:Session=Depends(get_db),u:User=Depends(require_roles('AUDITOR','SECURITY_APPROVER','KEY_CUSTODIAN','ADMIN'))):
    q=select(AuditLog).order_by(AuditLog.sequence_number.desc())
    if search:q=q.where(AuditLog.action.ilike(f'%{search}%'))
    return [{"sequence":a.sequence_number,"timestamp":a.timestamp,"actor_id":a.actor_id,"action":a.action,"resource_type":a.resource_type,"resource_id":a.resource_id,"event":json.loads(a.event_data_json),"previous_hash":a.previous_hash,"entry_hash":a.entry_hash} for a in db.scalars(q.limit(500)).all()]
@router.post('/audit/verify')
def verify(db:Session=Depends(get_db),u:User=Depends(require_roles('AUDITOR','SECURITY_APPROVER','KEY_CUSTODIAN','ADMIN'))):return verify_chain(db)
@router.get('/evidence')
def evidence(db:Session=Depends(get_db),u:User=Depends(current_user)):return [evidence_dict(e)|{"id":e.id} for e in db.scalars(select(EvidenceRecord).order_by(EvidenceRecord.evidence_created_at.desc())).all()]
@router.get('/evidence/{eid}/export/json')
def export_json(eid:int,db:Session=Depends(get_db),u:User=Depends(current_user)):
    e=db.get(EvidenceRecord,eid)
    if not e:raise HTTPException(404,'Evidence not found')
    return Response(json.dumps(evidence_dict(e),indent=2),media_type='application/json',headers={'Content-Disposition':f'attachment; filename={e.evidence_id}.json'})
@router.get('/evidence/{eid}/export/pdf')
def export_pdf(eid:int,db:Session=Depends(get_db),u:User=Depends(current_user)):
    e=db.get(EvidenceRecord,eid)
    if not e:raise HTTPException(404,'Evidence not found')
    return StreamingResponse(BytesIO(evidence_pdf(e)),media_type='application/pdf',headers={'Content-Disposition':f'attachment; filename={e.evidence_id}.pdf'})

@router.get('/monitoring')
def monitoring(db:Session=Depends(get_db),u:User=Depends(current_user)):
    ops=db.scalars(select(HSMOperation).order_by(HSMOperation.started_at)).all(); success=sum(o.status=='SUCCESS' for o in ops); total=len(ops); pending=db.scalar(select(func.count()).select_from(SigningRequest).where(SigningRequest.status.in_(['PENDING_SECURITY_APPROVAL','PENDING_RELEASE_APPROVAL']))) or 0
    return {"success_rate":round(success*100/total,2) if total else 100,"average_latency_ms":round(sum(o.latency_ms for o in ops)/total,1) if total else 0,"queue_depth":pending,"operations":[{"time":o.started_at,"status":o.status,"latency_ms":o.latency_ms} for o in ops[-50:]]}
@router.get('/users')
def users(db:Session=Depends(get_db),u:User=Depends(require_roles('ADMIN'))):return [user_json(x) for x in db.scalars(select(User).order_by(User.username)).all()]
@router.put('/users/{uid}/roles')
def roles(uid:int,data:RoleAssignment,db:Session=Depends(get_db),u:User=Depends(require_roles('ADMIN'))):
    target=db.get(User,uid)
    if not target:raise HTTPException(404,'User not found')
    found=db.scalars(select(Role).where(Role.name.in_([x.upper() for x in data.roles]))).all()
    if len(found)!=len(set(x.upper() for x in data.roles)):raise HTTPException(422,'Unknown role')
    target.roles=list(found);write_audit(db,u.id,'ROLES_UPDATED','USER',str(uid),{"roles":[r.name for r in found]});db.commit();return user_json(target)
@router.get('/settings')
def settings(db:Session=Depends(get_db),u:User=Depends(current_user)):return {s.setting_key:json.loads(s.setting_value_json) for s in db.scalars(select(SystemSetting)).all()}
@router.put('/settings/{key}')
def setting(key:str,data:SettingUpdate,db:Session=Depends(get_db),u:User=Depends(require_roles('ADMIN'))):
    s=db.scalar(select(SystemSetting).where(SystemSetting.setting_key==key))
    if not s:s=SystemSetting(setting_key=key,setting_value_json='null');db.add(s)
    s.setting_value_json=json.dumps(data.value);s.updated_by=u.id;write_audit(db,u.id,'SETTING_UPDATED','SETTING',key,{"value":data.value});db.commit();return {key:data.value}
