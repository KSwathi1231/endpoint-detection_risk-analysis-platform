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
@router.get("/latest")
def get_latest_endpoint_analysis():

    latest_analysis = endpoint_service.get_latest_analysis()

    if latest_analysis is None:
        return {
            "status": "no_data",
            "message": "No endpoint telemetry received yet"
        }

    return {
        "status": "success",
        "endpoint_analysis": latest_analysis
    }