from fastapi import APIRouter, HTTPException

from app.schemas.event_schema import NetworkEvent
from app.services.ml_service import ml_service
from app.services.behaviour_service import behaviour_service
from app.services.ioc_service import ioc_service
from app.services.risk_service import risk_service
from app.services.temporal_service import temporal_service
from app.services.correlation_service import correlation_service
from app.services.response_agent import response_agent
from app.services.incident_service import incident_service


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

        # Step 3: IOC analysis
        ioc_result = ioc_service.analyze_iocs(
            event_data
        )
        # Step 4: Temporal analysis
        temporal_result = temporal_service.analyze_temporal_pattern(
            event_data,
            ml_result
        )
        # Step 5: Correlation analysis
        correlation_result = correlation_service.correlate_events(
            ml_result,
            behaviour_result,
            ioc_result,
            temporal_result
        )

        # Step 6: Context-aware risk calculation
        risk_result = risk_service.calculate_risk(
            threat_probability=ml_result["threat_probability"],
            anomaly_score=ml_result["anomaly_score"],
            behaviour_score=behaviour_result["behaviour_score"],
            ioc_score=ioc_result["ioc_score"],
            temporal_score=temporal_result["temporal_score"],
            correlation_score=correlation_result["correlation_score"]
        )
        # Step 7: Response decision
        response_result = response_agent.determine_response(
            risk_result,
            correlation_result,
            ioc_result
        )
            # Step 8: Incident creation
        incident_result = incident_service.create_incident(
            risk_result=risk_result,
            response_result=response_result,
            analysis_result=ml_result
        )

        # Step 7: Return complete analysis
        return {
            "status": "success",
            "analysis": ml_result,
            "behaviour_analysis": behaviour_result,
            "ioc_analysis": ioc_result,
            "temporal_analysis": temporal_result,
            "risk_assessment": risk_result,
            "correlation_analysis": correlation_result,
            "response_decision": response_result,
            "incident": incident_result,
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )