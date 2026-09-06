import { useEffect, useState } from "react";
import {
  Brain,
  ShieldAlert,
  Activity,
  Cpu,
  Network,
  FileWarning,
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  Shield,
  Zap,
  RefreshCw,
} from "lucide-react";

import "./ThreatAnalysis.css";

const API_URL = "http://localhost:8000/endpoint/latest";

const ThreatAnalysis = () => {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchThreatAnalysis = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch(API_URL);

      if (!response.ok) {
        throw new Error("Failed to fetch threat analysis");
      }

      const data = await response.json();

      // Supports both direct response and wrapped response
      setAnalysis(data.endpoint_analysis || data);
    } catch (err) {
      console.error("Threat analysis error:", err);
      setError("Unable to load threat analysis data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreatAnalysis();
  }, []);

  const getSeverityClass = (severity) => {
    if (!severity) return "low";

    return severity.toLowerCase();
  };

  const formatScore = (score) => {
    if (score === undefined || score === null) return "0";
    return Number(score).toFixed(1);
  };

  if (loading) {
    return (
      <div className="threat-analysis-page loading-state">
        <RefreshCw className="spin" size={32} />
        <p>Analyzing endpoint threat intelligence...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="threat-analysis-page error-state">
        <AlertTriangle size={40} />
        <h2>Analysis Unavailable</h2>
        <p>{error}</p>
        <button onClick={fetchThreatAnalysis}>
          <RefreshCw size={18} />
          Retry
        </button>
      </div>
    );
  }

  const severity = analysis?.severity || "LOW";
  const severityClass = getSeverityClass(severity);

  const riskFactors = analysis?.risk_factors || {};
  const contributors = analysis?.risk_contributors || {};
  const escalation = analysis?.threat_escalation || {};
  const responseDecision = analysis?.response_decision || {};

  const suspiciousProcesses =
    contributors?.suspicious_processes || [];

  const suspiciousConnections =
    contributors?.suspicious_connections || [];

  const suspiciousFileEvents =
    contributors?.suspicious_file_events?.suspicious_file_events || [];

  const systemAnomaly =
    contributors?.system_anomaly || {};

  const riskReasons = analysis?.risk_reasons || [];

  const riskBreakdown = analysis?.risk_breakdown || {};

  return (
    <div className="threat-analysis-page">

      {/* HEADER */}

      <div className="threat-analysis-header">
        <div>
          <div className="page-title-row">
            <Brain size={30} />
            <h1>Threat Analysis</h1>
          </div>

          <p>
            AI-driven investigation and security reasoning for detected endpoint activity
          </p>
        </div>

        <button
          className="refresh-btn"
          onClick={fetchThreatAnalysis}
        >
          <RefreshCw size={18} />
          Refresh Analysis
        </button>
      </div>


      {/* THREAT SUMMARY */}

      <section className="threat-summary-grid">

        <div className={`threat-status-card ${severityClass}`}>
          <div className="status-card-icon">
            <ShieldAlert size={28} />
          </div>

          <div>
            <span>Threat Severity</span>
            <h2>{severity}</h2>
          </div>
        </div>


        <div className="threat-status-card">
          <div className="status-card-icon blue">
            <TrendingUp size={28} />
          </div>

          <div>
            <span>Risk Score</span>
            <h2>{formatScore(analysis?.risk_score)} / 100</h2>
          </div>
        </div>


        <div className="threat-status-card">
          <div className="status-card-icon purple">
            <Zap size={28} />
          </div>

          <div>
            <span>Threat Probability</span>
            <h2>
              {Math.round(
                (riskFactors?.threat_probability || 0) * 100
              )}%
            </h2>
          </div>
        </div>


        <div className="threat-status-card">
          <div className="status-card-icon orange">
            <Activity size={28} />
          </div>

          <div>
            <span>Response Priority</span>
            <h2>
              {responseDecision?.response_priority || "LOW"}
            </h2>
          </div>
        </div>

      </section>


      {/* AI ASSESSMENT */}

      <section className="analysis-card ai-assessment-card">

        <div className="section-header">
          <div className="section-title">
            <Brain size={22} />
            <div>
              <h2>AI Threat Assessment</h2>
              <p>
                Security reasoning generated from endpoint telemetry
              </p>
            </div>
          </div>
        </div>

        <div className="assessment-content">

          <div className={`assessment-severity ${severityClass}`}>
            <Shield size={40} />
            <div>
              <span>Current Assessment</span>
              <h3>{severity} RISK DETECTED</h3>
            </div>
          </div>

          <div className="assessment-reasons">
            <h3>Why was this classification made?</h3>

            {riskReasons.length > 0 ? (
              <ul>
                {riskReasons.map((reason, index) => (
                  <li key={index}>
                    <AlertTriangle size={16} />
                    {reason}
                  </li>
                ))}
              </ul>
            ) : (
              <div className="no-data">
                <CheckCircle size={18} />
                No significant threat indicators detected.
              </div>
            )}
          </div>

        </div>

      </section>


      {/* RISK FACTORS */}

      <section className="analysis-card">

        <div className="section-header">
          <div className="section-title">
            <TrendingUp size={22} />
            <div>
              <h2>Risk Intelligence Factors</h2>
              <p>
                Individual signals contributing to the security decision
              </p>
            </div>
          </div>
        </div>

        <div className="risk-factors-grid">

          <RiskFactor
            label="Threat Probability"
            value={riskFactors?.threat_probability}
          />

          <RiskFactor
            label="System Anomaly"
            value={riskFactors?.anomaly_score}
          />

          <RiskFactor
            label="Behaviour Analysis"
            value={riskFactors?.behaviour_score}
          />

          <RiskFactor
            label="IOC Detection"
            value={riskFactors?.ioc_score}
          />

          <RiskFactor
            label="Temporal Analysis"
            value={riskFactors?.temporal_score}
          />

          <RiskFactor
            label="Correlation Analysis"
            value={riskFactors?.correlation_score}
          />

        </div>

      </section>


      {/* DETECTED EVIDENCE */}

      <section className="analysis-card">

        <div className="section-header">
          <div className="section-title">
            <ShieldAlert size={22} />
            <div>
              <h2>Detection Evidence</h2>
              <p>
                Security evidence collected from endpoint monitoring
              </p>
            </div>
          </div>
        </div>


        <div className="evidence-grid">

          {/* PROCESS */}

          <div className="evidence-card">

            <div className="evidence-header">
              <div className="evidence-icon process">
                <Cpu size={22} />
              </div>

              <div>
                <h3>Suspicious Processes</h3>
                <span>{suspiciousProcesses.length} detected</span>
              </div>
            </div>

            <div className="evidence-content">

              {suspiciousProcesses.length > 0 ? (
                suspiciousProcesses.map((process, index) => (

                  <div className="process-evidence" key={index}>

                    <div className="process-top">
                      <strong>{process.name}</strong>

                      <span className="score-badge">
                        Score: {process.suspicion_score}
                      </span>
                    </div>

                    <div className="process-meta">
                      PID: {process.pid}
                    </div>

                    <div className="process-stats">
                      <span>
                        CPU: {formatScore(process.cpu_percent)}%
                      </span>

                      <span>
                        Memory: {formatScore(process.memory_percent)}%
                      </span>
                    </div>

                    {process.reasons?.length > 0 && (
                      <ul className="process-reasons">
                        {process.reasons.map((reason, i) => (
                          <li key={i}>{reason}</li>
                        ))}
                      </ul>
                    )}

                  </div>

                ))
              ) : (
                <p className="empty-evidence">
                  No suspicious processes detected
                </p>
              )}

            </div>

          </div>


          {/* NETWORK */}

          <div className="evidence-card">

            <div className="evidence-header">
              <div className="evidence-icon network">
                <Network size={22} />
              </div>

              <div>
                <h3>Network Indicators</h3>
                <span>
                  {suspiciousConnections.length} suspicious connections
                </span>
              </div>
            </div>

            <div className="evidence-content">

              {suspiciousConnections.length > 0 ? (
                suspiciousConnections.map((connection, index) => (

                  <div className="network-evidence" key={index}>
                    <strong>
                      {connection.remote_address || "Unknown Connection"}
                    </strong>

                    <p>
                      {connection.reason || "Suspicious network activity detected"}
                    </p>
                  </div>

                ))
              ) : (
                <p className="empty-evidence">
                  No suspicious network activity detected
                </p>
              )}

            </div>

          </div>


          {/* FILE */}

          <div className="evidence-card">

            <div className="evidence-header">
              <div className="evidence-icon file">
                <FileWarning size={22} />
              </div>

              <div>
                <h3>File Activity</h3>
                <span>
                  {suspiciousFileEvents.length} suspicious events
                </span>
              </div>
            </div>

            <div className="evidence-content">

              {suspiciousFileEvents.length > 0 ? (
                suspiciousFileEvents.map((file, index) => (

                  <div className="file-evidence" key={index}>
                    <strong>
                      {file.file_path || "Suspicious File"}
                    </strong>

                    <p>
                      {file.reason || "Suspicious file behavior detected"}
                    </p>
                  </div>

                ))
              ) : (
                <p className="empty-evidence">
                  No suspicious file activity detected
                </p>
              )}

            </div>

          </div>


          {/* SYSTEM */}

          <div className="evidence-card">

            <div className="evidence-header">
              <div className="evidence-icon anomaly">
                <Activity size={22} />
              </div>

              <div>
                <h3>System Anomaly</h3>

                <span>
                  {systemAnomaly?.anomaly_detected
                    ? "Anomaly detected"
                    : "Normal system behavior"}
                </span>
              </div>
            </div>

            <div className="anomaly-display">

              <div className="anomaly-score">
                {Math.round(
                  (systemAnomaly?.anomaly_score || 0) * 100
                )}%
              </div>

              <div className="anomaly-bar">
                <div
                  className="anomaly-progress"
                  style={{
                    width: `${Math.min(
                      (systemAnomaly?.anomaly_score || 0) * 100,
                      100
                    )}%`,
                  }}
                />
              </div>

            </div>

          </div>

        </div>

      </section>


      {/* RISK BREAKDOWN */}

      <section className="analysis-card">

        <div className="section-header">
          <div className="section-title">
            <Activity size={22} />

            <div>
              <h2>Risk Contribution Analysis</h2>
              <p>
                How each monitoring component contributed to the final risk score
              </p>
            </div>
          </div>
        </div>

        <div className="breakdown-list">

          <BreakdownItem
            label="Process Risk"
            value={riskBreakdown?.process_risk}
          />

          <BreakdownItem
            label="Network Risk"
            value={riskBreakdown?.network_risk}
          />

          <BreakdownItem
            label="File Risk"
            value={riskBreakdown?.file_risk}
          />

          <BreakdownItem
            label="System Risk"
            value={riskBreakdown?.system_risk}
          />

        </div>

      </section>


      {/* ESCALATION */}

      <section className="analysis-card escalation-card">

        <div className="section-header">
          <div className="section-title">
            <TrendingUp size={22} />

            <div>
              <h2>Threat Escalation Decision</h2>
              <p>
                Determines whether the detected activity requires increased security response
              </p>
            </div>
          </div>
        </div>

        <div className="escalation-content">

          <div
            className={`escalation-status ${
              escalation?.escalated ? "escalated" : "normal"
            }`}
          >
            {escalation?.escalated ? (
              <AlertTriangle size={28} />
            ) : (
              <CheckCircle size={28} />
            )}

            <div>
              <span>Escalation Status</span>

              <h3>
                {escalation?.escalated
                  ? "THREAT ESCALATED"
                  : "NO ESCALATION REQUIRED"}
              </h3>
            </div>
          </div>


          <div className="escalation-details">

            <div>
              <span>High Confidence Processes</span>
              <strong>
                {escalation?.high_confidence_process_count || 0}
              </strong>
            </div>

            <div>
              <span>Endpoint Impact</span>
              <strong>
                {escalation?.endpoint_impact_detected
                  ? "Detected"
                  : "Not Detected"}
              </strong>
            </div>

          </div>


          {escalation?.escalation_reasons?.length > 0 && (

            <div className="escalation-reasons">

              <h4>Escalation Reasons</h4>

              {escalation.escalation_reasons.map(
                (reason, index) => (
                  <div key={index}>
                    <AlertTriangle size={15} />
                    {reason}
                  </div>
                )
              )}

            </div>

          )}

        </div>

      </section>


      {/* RESPONSE DECISION */}

      <section className="analysis-card response-card">

        <div className="section-header">

          <div className="section-title">
            <Shield size={22} />

            <div>
              <h2>Automated Response Decision</h2>

              <p>
                Recommended security action based on the final threat classification
              </p>
            </div>
          </div>

        </div>


        <div className="response-content">

          <div className="response-priority">

            <span>Response Priority</span>

            <h2>
              {responseDecision?.response_priority || "LOW"}
            </h2>

          </div>


          <div className="recommended-actions">

            <h3>Recommended Actions</h3>

            {responseDecision?.recommended_actions?.length > 0 ? (

              responseDecision.recommended_actions.map(
                (action, index) => (

                  <div className="recommended-action" key={index}>
                    <CheckCircle size={17} />
                    {action}
                  </div>

                )
              )

            ) : (

              <p>No specific response actions required.</p>

            )}

          </div>


          {responseDecision?.response_command && (

            <div className="response-command">

              <h3>Automated Command</h3>

              <div className="command-box">

                <span>
                  {responseDecision.response_command.action}
                </span>

                {responseDecision.response_command.target_process && (
                  <small>
                    Target:{" "}
                    {responseDecision.response_command.target_process}
                  </small>
                )}

                {responseDecision.response_command.target_pid && (
                  <small>
                    PID:{" "}
                    {responseDecision.response_command.target_pid}
                  </small>
                )}

              </div>

            </div>

          )}

        </div>

      </section>

    </div>
  );
};


const RiskFactor = ({ label, value }) => {

  const percentage = Math.min(
    Math.max((value || 0) * 100, 0),
    100
  );

  return (

    <div className="risk-factor-item">

      <div className="risk-factor-header">
        <span>{label}</span>
        <strong>{Math.round(percentage)}%</strong>
      </div>

      <div className="risk-factor-bar">

        <div
          className="risk-factor-progress"
          style={{ width: `${percentage}%` }}
        />

      </div>

    </div>

  );
};


const BreakdownItem = ({ label, value }) => {

  const percentage = Math.min(
    Math.max(value || 0, 0),
    100
  );

  return (

    <div className="breakdown-item">

      <div className="breakdown-header">
        <span>{label}</span>
        <strong>+{Number(value || 0).toFixed(1)}</strong>
      </div>

      <div className="breakdown-bar">

        <div
          className="breakdown-progress"
          style={{ width: `${percentage}%` }}
        />

      </div>

    </div>

  );
};


export default ThreatAnalysis;