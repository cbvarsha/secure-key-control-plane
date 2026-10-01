import json
from datetime import datetime,timedelta,timezone
from app.models import *
from app.services.policy_engine import evaluate

def test_policy_accepts_valid_request(db):
    role=Role(name='DEVELOPER');u=User(email='d@x',username='d',full_name='D',password_hash='x',roles=[role]);h=HSMPartition(partition_name='sim',slot_number=1);db.add_all([role,u,h]);db.flush();k=SigningKey(key_id='K1',display_name='k',algorithm='RSA-3072/SHA-256',environment='PRODUCTION',status='ACTIVE',hsm_partition_id=h.id,certificate_subject='x',certificate_serial='1',certificate_expiry=datetime.now(timezone.utc)+timedelta(days=1),expires_at=datetime.now(timezone.utc)+timedelta(days=1));db.add(k);db.flush();p=Policy(name='p',environment='PRODUCTION',created_by=u.id);db.add(p);db.flush();db.add_all([PolicyRule(policy_id=p.id,rule_type='ALLOWED_ALGORITHMS',configuration_json=json.dumps(['RSA-3072/SHA-256'])),PolicyRule(policy_id=p.id,rule_type='ALLOWED_ARTIFACT_TYPES',configuration_json=json.dumps(['JAR'])),PolicyRule(policy_id=p.id,rule_type='REQUIRED_APPROVALS',configuration_json=json.dumps(['SECURITY','RELEASE']))]);r=SigningRequest(request_number='SR-1',requester_id=u.id,artifact_name='a.jar',artifact_type='JAR',artifact_sha256='a'*64,environment='PRODUCTION',purpose='test',requested_key_id=k.id);db.add(r);db.flush();ok,results=evaluate(db,r,u);assert ok;assert all(x.passed for x in results)
