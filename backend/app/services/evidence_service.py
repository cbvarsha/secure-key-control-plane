import hashlib, io, json, secrets
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models import Approval, EvidenceRecord, PolicyResult, SigningRequest

def create_evidence(db:Session, req:SigningRequest, operation_id:str, simulated_signature:str)->EvidenceRecord:
    approvals=db.scalars(select(Approval).where(Approval.signing_request_id==req.id)).all()
    names={a.approval_type:a.approver.full_name for a in approvals}
    results=db.scalars(select(PolicyResult).where(PolicyResult.signing_request_id==req.id)).all()
    snapshot=[{"rule":r.rule_type,"passed":r.passed,"actual":r.actual_value,"expected":r.expected_value} for r in results]
    eid=f"EVD-{secrets.token_hex(6).upper()}"
    payload={"evidence_id":eid,"request":req.request_number,"artifact_sha256":req.artifact_sha256,"key_id":req.requested_key.key_id,"algorithm":req.requested_key.algorithm,"operation_id":operation_id,"simulated_signature":simulated_signature,"policy":snapshot}
    eh=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    row=EvidenceRecord(evidence_id=eid,signing_request_id=req.id,artifact_name=req.artifact_name,artifact_sha256=req.artifact_sha256,key_id=req.requested_key.key_id,algorithm=req.requested_key.algorithm,simulated_signature=simulated_signature,security_approver=names.get("SECURITY"),release_approver=names.get("RELEASE"),policy_snapshot_json=json.dumps(snapshot),hsm_operation_id=operation_id,request_created_at=req.created_at,signed_at=req.signed_at,evidence_sha256=eh)
    db.add(row); db.flush()
    return row

def evidence_dict(e:EvidenceRecord)->dict:
    return {"evidence_id":e.evidence_id,"artifact_name":e.artifact_name,"artifact_sha256":e.artifact_sha256,"key_id":e.key_id,"algorithm":e.algorithm,"signature_type":"SIMULATED SIGNATURE","simulated_signature":e.simulated_signature,"security_approver":e.security_approver,"release_approver":e.release_approver,"policy_results":json.loads(e.policy_snapshot_json),"hsm_operation_id":e.hsm_operation_id,"signed_at":e.signed_at.isoformat(),"evidence_sha256":e.evidence_sha256,"limitation":"Generated using the portfolio application's Simulated HSM; not production cryptographic signing."}

def evidence_pdf(e:EvidenceRecord)->bytes:
    buf=io.BytesIO()
    doc=SimpleDocTemplate(buf,pagesize=A4)
    styles=getSampleStyleSheet()
    d=evidence_dict(e)
    story=[Paragraph("Code-Signing Evidence",styles["Title"]),Paragraph("SIMULATED HSM — PORTFOLIO ENVIRONMENT",styles["Heading2"]),Spacer(1,12)]
    for k,v in d.items():
        story.append(Paragraph(f"<b>{k.replace('_',' ').title()}:</b> {str(v)}",styles["BodyText"]))
        story.append(Spacer(1,6))
    doc.build(story)
    return buf.getvalue()
