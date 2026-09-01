from fastapi import APIRouter, HTTPException

from app.schemas.event_schema import NetworkEvent
from app.services.ml_service import ml_service
from app.services.risk_service import risk_service
from app.services.behaviour_service import behaviour_service


router = APIRouter(
    prefix="/events",
    tags=["Threat Analysis"]
)


@router.post("/analyze")
def analyze_event(event: NetworkEvent):

    try:
        # Convert validated event to dictionary
        event_data = event.to_dict()

        # Step 1: ML analysis
        ml_result = ml_service.analyze(event_data)

        # Step 2: Behaviour analysis
        behaviour_result = behaviour_service.analyze_behaviour(
            event_data
        )

        # Step 3: Calculate contextual risk
        risk_result = risk_service.calculate_risk(
            threat_probability=ml_result["threat_probability"],
            anomaly_score=ml_result["anomaly_score"],
            behaviour_score=behaviour_result["behaviour_score"]
        )

        # Step 4: Return complete analysis
        return {
            "status": "success",
            "analysis": ml_result,
            "behaviour_analysis": behaviour_result,
            "risk_assessment": risk_result
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )