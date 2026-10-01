import json, os, sys
from datetime import datetime, timedelta, timezone
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from sqlalchemy import select
from app.database import Base, SessionLocal, engine
from app.models import *
from app.security.passwords import hash_password
from app.services.audit_service import write_audit

Base.metadata.create_all(bind=engine)
db=SessionLocal()
try:
    if db.scalar(select(User).limit(1)):
        print("Database already seeded")
        raise SystemExit(0)
    demo_password=os.getenv("DEMO_PASSWORD","demo-password-change-me")
    roles={n:Role(name=n,description=n.replace("_"," ").title()) for n in ["DEVELOPER","SECURITY_APPROVER","RELEASE_MANAGER","KEY_CUSTODIAN","AUDITOR","ADMIN"]}
    db.add_all(roles.values()); db.flush()
    specs=[("developer","developer@controlplane.local","Developer","DEVELOPER"),("security","security@controlplane.local","Security Approver","SECURITY_APPROVER"),("release","release@controlplane.local","Release Manager","RELEASE_MANAGER"),("custodian","custodian@controlplane.local","Key Custodian","KEY_CUSTODIAN"),("auditor","auditor@controlplane.local","Auditor","AUDITOR"),("admin","admin@controlplane.local","Administrator","ADMIN")]
    users={}
    for username,email,name,role in specs:
        u=User(username=username,email=email,full_name=name,password_hash=hash_password(demo_password),roles=[roles[role]])
        db.add(u); users[username]=u
    db.flush()
    now=datetime.now(timezone.utc)
    partitions=[HSMPartition(partition_name="SIM-HSM-Cluster-01",status="HEALTHY",slot_number=1,latency_ms=12,capacity_percent=32),HSMPartition(partition_name="SIM-HSM-Cluster-02",status="HEALTHY",slot_number=2,latency_ms=15,capacity_percent=41),HSMPartition(partition_name="SIM-HSM-DR-01",status="HEALTHY",slot_number=3,latency_ms=23,capacity_percent=18)]
    db.add_all(partitions); db.flush()
    keys=[
      SigningKey(key_id="PROD-CODESIGN-01",display_name="Production Code Signing",algorithm="RSA-3072/SHA-256",environment="PRODUCTION",status="ACTIVE",hsm_partition_id=partitions[0].id,certificate_subject="CN=Production Code Signing,O=Portfolio",certificate_serial="A1B2C3D4",certificate_expiry=now+timedelta(days=287),expires_at=now+timedelta(days=287),usage_count=72),
      SigningKey(key_id="DEV-CODESIGN-01",display_name="Development Code Signing",algorithm="ECDSA-P256/SHA-256",environment="DEVELOPMENT",status="ACTIVE",hsm_partition_id=partitions[1].id,certificate_subject="CN=Development Code Signing,O=Portfolio",certificate_serial="D4C3B2A1",certificate_expiry=now+timedelta(days=420),expires_at=now+timedelta(days=420),usage_count=39),
      SigningKey(key_id="STAGE-CODESIGN-01",display_name="Staging Code Signing",algorithm="RSA-3072/SHA-256",environment="STAGING",status="ACTIVE",hsm_partition_id=partitions[0].id,certificate_subject="CN=Staging Code Signing,O=Portfolio",certificate_serial="778899AA",certificate_expiry=now+timedelta(days=180),expires_at=now+timedelta(days=180),usage_count=51)]
    db.add_all(keys); db.flush()
    for env,required in [("PRODUCTION",["SECURITY","RELEASE"]),("STAGING",["SECURITY"]),("DEVELOPMENT",["SECURITY"])]:
        p=Policy(name=f"{env.title()} Signing Policy",description=f"Code-signing policy for {env}",environment=env,created_by=users["admin"].id)
        db.add(p); db.flush()
        db.add_all([
          PolicyRule(policy_id=p.id,rule_type="ALLOWED_ALGORITHMS",configuration_json=json.dumps(["RSA-3072/SHA-256","ECDSA-P256/SHA-256"])),
          PolicyRule(policy_id=p.id,rule_type="ALLOWED_ARTIFACT_TYPES",configuration_json=json.dumps(["JAR","ZIP","MSI","EXE","APK"])),
          PolicyRule(policy_id=p.id,rule_type="REQUIRED_APPROVALS",configuration_json=json.dumps(required))])
    for key,value in {"default_environment":"PRODUCTION","approval_sla_hours":4,"request_retention_days":365,"monitoring_refresh_seconds":30}.items():
        db.add(SystemSetting(setting_key=key,setting_value_json=json.dumps(value),updated_by=users["admin"].id))
    write_audit(db,users["admin"].id,"SYSTEM_SEEDED","SYSTEM","seed",{"simulated_hsm":True})
    db.commit()
    print("Seed complete. Demo password is controlled by DEMO_PASSWORD.")
finally:
    db.close()
