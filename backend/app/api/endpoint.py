from fastapi import APIRouter
from app.services.endpoint_service import endpoint_service


router = APIRouter(
    prefix="/endpoint",
    tags=["Endpoint Monitoring"]
)


@router.post("/telemetry")
def receive_endpoint_telemetry(telemetry: dict):
    """
    Receive telemetry collected from the Endpoint Agent
    and perform endpoint-level security analysis.
    """

    result = endpoint_service.analyze_telemetry(telemetry)

    return {
        "status": "success",
        "endpoint_analysis": result
    }