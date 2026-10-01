from app.services.audit_service import write_audit,verify_chain
from app.models import AuditLog

def test_audit_hash_chain_detects_tampering(db):
    write_audit(db,None,'ONE','TEST','1',{'a':1});write_audit(db,None,'TWO','TEST','2',{'b':2});db.commit();assert verify_chain(db)['valid'] is True
    row=db.query(AuditLog).filter_by(sequence_number=1).one();row.event_data_json='{"tampered":true}';db.commit();result=verify_chain(db);assert result['valid'] is False;assert result['broken_at']==1
