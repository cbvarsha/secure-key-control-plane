from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator

class ORMModel(BaseModel): model_config = ConfigDict(from_attributes=True)
class LoginRequest(BaseModel): username: str; password: str
class ApprovalAction(BaseModel): comment: str = Field(min_length=3, max_length=1000)
class RequestCreate(BaseModel):
    artifact_name: str = Field(min_length=1, max_length=255)
    artifact_sha256: str
    environment: str
    purpose: str = Field(min_length=3, max_length=255)
    requested_key_id: int
    @field_validator("artifact_sha256")
    @classmethod
    def sha(cls, v: str) -> str:
        v=v.lower().strip()
        if len(v)!=64 or any(c not in "0123456789abcdef" for c in v): raise ValueError("Must be a 64-character SHA-256 hex digest")
        return v
class KeyLifecycleAction(BaseModel): action: str; reason: str = Field(min_length=3, max_length=500)
class PolicyUpdate(BaseModel): allowed_algorithms: list[str]; allowed_artifact_types: list[str]; required_approvals: list[str]
class RoleAssignment(BaseModel): roles: list[str]
class SettingUpdate(BaseModel): value: object
