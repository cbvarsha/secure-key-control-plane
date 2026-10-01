import json
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from app.models import Policy, PolicyRule, PolicyResult, SigningRequest, User

def artifact_type(name:str)->str:
    suffix=Path(name).suffix.replace(".","").upper(); return suffix or "UNKNOWN"
def _rules(db:Session, policy_id:int)->dict[str,object]:
    out={}
    for r in db.scalars(select(PolicyRule).where(PolicyRule.policy_id==policy_id,PolicyRule.enabled.is_(True))): out[r.rule_type]=json.loads(r.configuration_json)
    return out
def evaluate(db:Session, req:SigningRequest, user:User)->tuple[bool,list[PolicyResult]]:
    policy=db.scalar(select(Policy).where(Policy.environment==req.environment,Policy.enabled.is_(True)))
    if not policy: raise ValueError(f"No enabled policy for {req.environment}")
    rules=_rules(db,policy.id); key=req.requested_key; now=datetime.now(timezone.utc); roles={r.name for r in user.roles}
    expires=key.expires_at if key.expires_at.tzinfo else key.expires_at.replace(tzinfo=timezone.utc)
    checks=[
      ("USER_PERMITTED", bool(roles & {"DEVELOPER","ADMIN"}), sorted(roles), ["DEVELOPER","ADMIN"]),
      ("ARTIFACT_TYPE_ALLOWED", req.artifact_type in rules.get("ALLOWED_ARTIFACT_TYPES",[]), req.artifact_type, rules.get("ALLOWED_ARTIFACT_TYPES",[])),
      ("KEY_ACTIVE", key.status=="ACTIVE", key.status, "ACTIVE"),
      ("KEY_NOT_EXPIRED", expires>now, expires.isoformat(), f"> {now.isoformat()}"),
      ("ALGORITHM_ALLOWED", key.algorithm in rules.get("ALLOWED_ALGORITHMS",[]), key.algorithm, rules.get("ALLOWED_ALGORITHMS",[])),
      ("KEY_ENVIRONMENT_ALLOWED", key.environment in {req.environment,"ALL"}, key.environment, req.environment),
    ]
    db.execute(delete(PolicyResult).where(PolicyResult.signing_request_id==req.id)); results=[]
    for typ,passed,actual,expected in checks:
        row=PolicyResult(signing_request_id=req.id,policy_id=policy.id,rule_type=typ,passed=passed,actual_value=json.dumps(actual),expected_value=json.dumps(expected),message=("Passed" if passed else "Failed")); db.add(row); results.append(row)
    db.flush(); return all(x.passed for x in results),results
def required_approvals(db:Session, environment:str)->list[str]:
    p=db.scalar(select(Policy).where(Policy.environment==environment,Policy.enabled.is_(True))); rules=_rules(db,p.id) if p else {}; return list(rules.get("REQUIRED_APPROVALS",["SECURITY"]))
