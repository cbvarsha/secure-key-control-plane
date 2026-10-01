import pytest
from fastapi import HTTPException
from app.models import User,Role,SigningRequest,HSMPartition,SigningKey
from app.services.workflow_service import decide
from datetime import datetime,timedelta,timezone

def test_requester_cannot_approve_own_request(db):
    role=Role(name='SECURITY_APPROVER');u=User(email='x@x',username='x',full_name='X',password_hash='x',roles=[role]);h=HSMPartition(partition_name='sim',slot_number=1);db.add_all([role,u,h]);db.flush();k=SigningKey(key_id='K',display_name='k',algorithm='RSA-3072/SHA-256',environment='PRODUCTION',hsm_partition_id=h.id,certificate_subject='x',certificate_serial='1',certificate_expiry=datetime.now(timezone.utc)+timedelta(days=1),expires_at=datetime.now(timezone.utc)+timedelta(days=1));db.add(k);db.flush();r=SigningRequest(request_number='SR-X',requester_id=u.id,artifact_name='a.jar',artifact_type='JAR',artifact_sha256='a'*64,environment='PRODUCTION',purpose='x',requested_key_id=k.id,status='PENDING_SECURITY_APPROVAL');db.add(r);db.flush()
    with pytest.raises(HTTPException) as e: decide(db,r,u,'SECURITY','APPROVED','looks good')
    assert e.value.status_code==403
