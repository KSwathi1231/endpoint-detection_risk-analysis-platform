from fastapi import FastAPI

from app.api.events import router as events_router
from app.api.incidents import router as incidents_router
from app.api.endpoint import router as endpoint_router
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(
    title="AI-Driven Endpoint Defense Platform",
    description="Context-Aware Endpoint Threat Detection and Risk Analysis",
    version="1.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "AI-Driven Endpoint Defense Platform is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "backend"
    }


# Include event analysis routes
app.include_router(events_router)
app.include_router(incidents_router)
app.include_router(endpoint_router)