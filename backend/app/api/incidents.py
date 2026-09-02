from fastapi import APIRouter, HTTPException
from app.services.incident_service import incident_service


router = APIRouter(
    prefix="/incidents",
    tags=["Incident Management"]
)


@router.get("/")
def get_incidents():
    """
    Retrieve all security incidents.
    """
    return {
        "total_incidents": len(incident_service.get_all_incidents()),
        "incidents": incident_service.get_all_incidents()
    }


@router.get("/{incident_id}")
def get_incident(incident_id: str):
    """
    Retrieve a specific incident using its ID.
    """
    incident = incident_service.get_incident_by_id(incident_id)

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return incident