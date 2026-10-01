from fastapi import APIRouter
from app.api.routes.all_routes import router as all_router
router=APIRouter()
router.include_router(all_router)
