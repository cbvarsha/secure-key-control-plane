from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base

def now() -> datetime: return datetime.now(timezone.utc)

class User(Base):
    __tablename__="users"
    id:Mapped[int]=mapped_column(primary_key=True)
    email:Mapped[str]=mapped_column(String(255),unique=True,index=True)
    username:Mapped[str]=mapped_column(String(80),unique=True,index=True)
    full_name:Mapped[str]=mapped_column(String(160))
    password_hash:Mapped[str]=mapped_column(String(255))
    is_active:Mapped[bool]=mapped_column(Boolean,default=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now,onupdate=now)
    last_login_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    roles:Mapped[list["Role"]]=relationship(secondary="user_roles",back_populates="users")

class Role(Base):
    __tablename__="roles"
    id:Mapped[int]=mapped_column(primary_key=True)
    name:Mapped[str]=mapped_column(String(50),unique=True)
    description:Mapped[str]=mapped_column(String(255),default="")
    users:Mapped[list[User]]=relationship(secondary="user_roles",back_populates="roles")

class UserRole(Base):
    __tablename__="user_roles"
    user_id:Mapped[int]=mapped_column(ForeignKey("users.id",ondelete="CASCADE"),primary_key=True)
    role_id:Mapped[int]=mapped_column(ForeignKey("roles.id",ondelete="CASCADE"),primary_key=True)

class HSMPartition(Base):
    __tablename__="hsm_partitions"
    id:Mapped[int]=mapped_column(primary_key=True)
    partition_name:Mapped[str]=mapped_column(String(100),unique=True)
    status:Mapped[str]=mapped_column(String(30),default="HEALTHY")
    slot_number:Mapped[int]=mapped_column(Integer)
    latency_ms:Mapped[int]=mapped_column(Integer,default=10)
    capacity_percent:Mapped[int]=mapped_column(Integer,default=25)
    last_health_check:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)

class SigningKey(Base):
    __tablename__="signing_keys"
    id:Mapped[int]=mapped_column(primary_key=True)
    key_id:Mapped[str]=mapped_column(String(100),unique=True,index=True)
    display_name:Mapped[str]=mapped_column(String(160))
    algorithm:Mapped[str]=mapped_column(String(80))
    environment:Mapped[str]=mapped_column(String(30))
    status:Mapped[str]=mapped_column(String(30),default="ACTIVE")
    hsm_partition_id:Mapped[int]=mapped_column(ForeignKey("hsm_partitions.id"))
    certificate_subject:Mapped[str]=mapped_column(String(255))
    certificate_serial:Mapped[str]=mapped_column(String(100))
    certificate_expiry:Mapped[datetime]=mapped_column(DateTime(timezone=True))
    activated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    expires_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
    usage_count:Mapped[int]=mapped_column(Integer,default=0)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now,onupdate=now)
    hsm_partition:Mapped[HSMPartition]=relationship()

class SigningRequest(Base):
    __tablename__="signing_requests"
    id:Mapped[int]=mapped_column(primary_key=True)
    request_number:Mapped[str]=mapped_column(String(40),unique=True,index=True)
    requester_id:Mapped[int]=mapped_column(ForeignKey("users.id"))
    artifact_name:Mapped[str]=mapped_column(String(255))
    artifact_type:Mapped[str]=mapped_column(String(30))
    artifact_sha256:Mapped[str]=mapped_column(String(64))
    environment:Mapped[str]=mapped_column(String(30))
    purpose:Mapped[str]=mapped_column(String(255))
    requested_key_id:Mapped[int]=mapped_column(ForeignKey("signing_keys.id"))
    status:Mapped[str]=mapped_column(String(50),default="CREATED",index=True)
    policy_validated_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    approved_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    signing_started_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    signed_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    rejected_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    failed_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    failure_reason:Mapped[str|None]=mapped_column(Text,nullable=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now,onupdate=now)
    requester:Mapped[User]=relationship(foreign_keys=[requester_id])
    requested_key:Mapped[SigningKey]=relationship()

class Approval(Base):
    __tablename__="approvals"
    __table_args__=(UniqueConstraint("signing_request_id","approval_type",name="uq_request_approval_type"),)
    id:Mapped[int]=mapped_column(primary_key=True)
    signing_request_id:Mapped[int]=mapped_column(ForeignKey("signing_requests.id",ondelete="CASCADE"))
    approval_type:Mapped[str]=mapped_column(String(30))
    approver_id:Mapped[int]=mapped_column(ForeignKey("users.id"))
    decision:Mapped[str]=mapped_column(String(20))
    comment:Mapped[str]=mapped_column(Text)
    decided_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    approver:Mapped[User]=relationship()

class Policy(Base):
    __tablename__="policies"
    id:Mapped[int]=mapped_column(primary_key=True)
    name:Mapped[str]=mapped_column(String(160))
    description:Mapped[str]=mapped_column(Text,default="")
    environment:Mapped[str]=mapped_column(String(30),unique=True)
    enabled:Mapped[bool]=mapped_column(Boolean,default=True)
    version:Mapped[int]=mapped_column(Integer,default=1)
    created_by:Mapped[int]=mapped_column(ForeignKey("users.id"))
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now,onupdate=now)

class PolicyRule(Base):
    __tablename__="policy_rules"
    id:Mapped[int]=mapped_column(primary_key=True)
    policy_id:Mapped[int]=mapped_column(ForeignKey("policies.id",ondelete="CASCADE"))
    rule_type:Mapped[str]=mapped_column(String(80))
    configuration_json:Mapped[str]=mapped_column(Text)
    enabled:Mapped[bool]=mapped_column(Boolean,default=True)

class PolicyResult(Base):
    __tablename__="policy_results"
    id:Mapped[int]=mapped_column(primary_key=True)
    signing_request_id:Mapped[int]=mapped_column(ForeignKey("signing_requests.id",ondelete="CASCADE"))
    policy_id:Mapped[int]=mapped_column(ForeignKey("policies.id"))
    rule_type:Mapped[str]=mapped_column(String(80))
    passed:Mapped[bool]=mapped_column(Boolean)
    actual_value:Mapped[str]=mapped_column(Text)
    expected_value:Mapped[str]=mapped_column(Text)
    message:Mapped[str]=mapped_column(Text)
    evaluated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)

class HSMOperation(Base):
    __tablename__="hsm_operations"
    id:Mapped[int]=mapped_column(primary_key=True)
    operation_id:Mapped[str]=mapped_column(String(80),unique=True)
    partition_id:Mapped[int]=mapped_column(ForeignKey("hsm_partitions.id"))
    key_id:Mapped[int]=mapped_column(ForeignKey("signing_keys.id"))
    signing_request_id:Mapped[int]=mapped_column(ForeignKey("signing_requests.id"))
    operation_type:Mapped[str]=mapped_column(String(40),default="SIMULATED_SIGN")
    status:Mapped[str]=mapped_column(String(30))
    latency_ms:Mapped[int]=mapped_column(Integer)
    signature_algorithm:Mapped[str]=mapped_column(String(80))
    artifact_sha256:Mapped[str]=mapped_column(String(64))
    started_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    completed_at:Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    error_message:Mapped[str|None]=mapped_column(Text,nullable=True)

class EvidenceRecord(Base):
    __tablename__="evidence_records"
    id:Mapped[int]=mapped_column(primary_key=True)
    evidence_id:Mapped[str]=mapped_column(String(80),unique=True)
    signing_request_id:Mapped[int]=mapped_column(ForeignKey("signing_requests.id"),unique=True)
    artifact_name:Mapped[str]=mapped_column(String(255))
    artifact_sha256:Mapped[str]=mapped_column(String(64))
    key_id:Mapped[str]=mapped_column(String(100))
    algorithm:Mapped[str]=mapped_column(String(80))
    simulated_signature:Mapped[str]=mapped_column(Text)
    security_approver:Mapped[str|None]=mapped_column(String(160),nullable=True)
    release_approver:Mapped[str|None]=mapped_column(String(160),nullable=True)
    policy_snapshot_json:Mapped[str]=mapped_column(Text)
    hsm_operation_id:Mapped[str]=mapped_column(String(80))
    request_created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
    signed_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
    evidence_created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    evidence_sha256:Mapped[str]=mapped_column(String(64))

class AuditLog(Base):
    __tablename__="audit_logs"
    id:Mapped[int]=mapped_column(primary_key=True)
    sequence_number:Mapped[int]=mapped_column(Integer,unique=True,index=True)
    timestamp:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
    actor_id:Mapped[int|None]=mapped_column(ForeignKey("users.id"),nullable=True)
    action:Mapped[str]=mapped_column(String(100))
    resource_type:Mapped[str]=mapped_column(String(80))
    resource_id:Mapped[str]=mapped_column(String(100))
    event_data_json:Mapped[str]=mapped_column(Text)
    previous_hash:Mapped[str]=mapped_column(String(64))
    entry_hash:Mapped[str]=mapped_column(String(64),unique=True)

class KeyLifecycleEvent(Base):
    __tablename__="key_lifecycle_events"
    id:Mapped[int]=mapped_column(primary_key=True)
    key_id:Mapped[int]=mapped_column(ForeignKey("signing_keys.id",ondelete="CASCADE"))
    action:Mapped[str]=mapped_column(String(30))
    previous_status:Mapped[str]=mapped_column(String(30))
    new_status:Mapped[str]=mapped_column(String(30))
    performed_by:Mapped[int]=mapped_column(ForeignKey("users.id"))
    reason:Mapped[str]=mapped_column(Text)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)

class SystemSetting(Base):
    __tablename__="system_settings"
    id:Mapped[int]=mapped_column(primary_key=True)
    setting_key:Mapped[str]=mapped_column(String(100),unique=True)
    setting_value_json:Mapped[str]=mapped_column(Text)
    updated_by:Mapped[int|None]=mapped_column(ForeignKey("users.id"),nullable=True)
    updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now,onupdate=now)
