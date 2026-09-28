from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from api.routes.upload import router as upload_router
from api.routes.analysis import router as analysis_router
from api.routes.intelligence import router as intelligence_router
from auth.routes import router as auth_router

from database import init_db, SessionLocal
from core.job_manager import SQLAlchemyJobRepository, set_repository, reconcile_startup_state

from utils.debug import debug_log, debug_stage, debug_error


# ==============================
# LIFESPAN
# ==============================
@asynccontextmanager
async def lifespan(app: FastAPI):
    debug_stage("APPLICATION START")
    debug_log("Status", "Backend is starting...")

    # Integration fix: without this, core/job_manager.py silently falls
    # back to its module-level default InMemoryJobRepository() — job
    # state would not survive a restart and would not use
    # models.JobRecord at all. Production must use the persistent
    # SQLAlchemyJobRepository backed by the existing database.py
    # engine/session factory.
    init_db()
    set_repository(SQLAlchemyJobRepository(SessionLocal))
    reconciled = reconcile_startup_state()
    debug_log("Job lifecycle", f"repository=SQLAlchemyJobRepository reconciled={reconciled}")

    yield
    debug_log("Status", "Backend is shutting down...")


# ==============================
# APP INIT
# ==============================
app = FastAPI(
    title="AutoRev MCP",
    description="AI Assisted Reverse Engineering Platform",
    version="1.0",
    lifespan=lifespan,
)


# ==============================
# CORS (FIXED POSITION)
# ==============================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==============================
# ROUTES
# ==============================
app.include_router(auth_router)
app.include_router(upload_router)
app.include_router(analysis_router)
app.include_router(intelligence_router, prefix="/intelligence")


# ==============================
# ROOT ENDPOINT
# ==============================
@app.get("/")
def root():
    debug_log("Root Endpoint Hit", "OK")
    return {"message": "AutoRev MCP backend running"}


# ==============================
# HEALTH CHECK
# ==============================
@app.get("/health")
def health():
    debug_log("Health Check", "Healthy")
    return {"status": "healthy"}


# ==============================
# GLOBAL ERROR HANDLER
# ==============================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    debug_error("Unhandled Exception", exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "details": "unexpected error",
        },
    )