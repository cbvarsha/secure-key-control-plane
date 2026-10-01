from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.router import router
from app.config import get_settings
from app.database import Base, engine
import app.models

s = get_settings()
app = FastAPI(title=s.app_name, version="1.0.0", description="Portfolio control plane using a Simulated HSM. No production HSM integration.")
app.add_middleware(CORSMiddleware, allow_origins=s.cors_origin_list, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(router, prefix=s.api_prefix)

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

@app.get("/health")
def health():
    return {"status":"ok","hsm":"Simulated HSM","production_hsm_integration":False}
