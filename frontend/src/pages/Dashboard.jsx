import { useEffect, useState } from "react";
import {
  Monitor,
  ShieldAlert,
  AlertTriangle,
  Activity,
  Cpu,
  Network,
  FileWarning,
  Server,
  ChevronRight,
} from "lucide-react";

import StatCard from "../components/StatCard";
import {
  getLatestEndpointAnalysis,
  getIncidents,
} from "../services/api";

import "./Dashboard.css";

const Dashboard = () => {
  const [endpointData, setEndpointData] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchDashboardData = async () => {
    try {
      const [endpointResponse, incidentsResponse] = await Promise.all([
        getLatestEndpointAnalysis(),
        getIncidents(),
      ]);

      if (endpointResponse.data.status === "success") {
        setEndpointData(endpointResponse.data.endpoint_analysis);
      }

      setIncidents(incidentsResponse.data.incidents || []);
    } catch (error) {
      console.error("Error fetching dashboard data:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();

    // Refresh dashboard every 5 seconds
    const interval = setInterval(fetchDashboardData, 5000);

    return () => clearInterval(interval);
  }, []);

  const totalIncidents = incidents.length;

  const criticalThreats = incidents.filter(
    (incident) => incident.severity === "CRITICAL"
  ).length;

  const riskScore = endpointData
    ? endpointData.risk_score
    : "N/A";

  const severity = endpointData
    ? endpointData.severity
    : "No Data";
  const riskBreakdown = endpointData?.risk_breakdown || {
  process_risk: 0,
  network_risk: 0,
  file_risk: 0,
  system_risk: 0,
};

const riskContributors = endpointData?.risk_contributors || {
  suspicious_processes: [],
  suspicious_connections: [],
  suspicious_file_events: {
    suspicious_file_events: [],
  },
  system_anomaly: {},
};

const suspiciousProcesses =
  riskContributors.suspicious_processes || [];

const suspiciousConnections =
  riskContributors.suspicious_connections || [];

const suspiciousFiles =
  riskContributors.suspicious_file_events
    ?.suspicious_file_events || [];

  return (
    <div className="dashboard">
      <div className="dashboard-heading">
        <div>
          <h1>Security Overview</h1>
          <p>
            Monitor and analyze your endpoint security status
          </p>
        </div>

        <div className="live-status">
          <span className="live-dot"></span>
          {loading ? "Connecting..." : "Live Monitoring"}
        </div>
      </div>

      <div className="stats-grid">
        <StatCard
          title="Active Endpoints"
          value="1"
          subtitle="Endpoint agent connected"
          icon={<Monitor size={24} />}
          type="primary"
        />

        <StatCard
          title="Total Incidents"
          value={totalIncidents}
          subtitle="Detected security incidents"
          icon={<ShieldAlert size={24} />}
          type="warning"
        />

        <StatCard
          title="Critical Threats"
          value={criticalThreats}
          subtitle="Requires immediate attention"
          icon={<AlertTriangle size={24} />}
          type="danger"
        />

        <StatCard
          title="System Risk"
          value={riskScore}
          subtitle={`Current severity: ${severity}`}
          icon={<Activity size={24} />}
          type={
            severity === "CRITICAL" || severity === "HIGH"
              ? "danger"
              : severity === "MEDIUM"
              ? "warning"
              : "success"
          }
        />
      </div>
      <div className="risk-analysis-section">

  {/* Risk Breakdown */}
  <div className="risk-panel">
    <div className="panel-header">
      <div>
        <h2>Security Risk Breakdown</h2>
        <p>Risk contribution by monitoring component</p>
      </div>
    </div>

    <div className="risk-breakdown-list">

      <div className="risk-breakdown-item">
        <div className="breakdown-label">
          <div className="breakdown-icon process-icon">
            <Cpu size={20} />
          </div>

          <span>Suspicious Processes</span>
        </div>

        <strong>+{riskBreakdown.process_risk}</strong>
      </div>

      <div className="risk-breakdown-item">
        <div className="breakdown-label">
          <div className="breakdown-icon network-icon">
            <Network size={20} />
          </div>

          <span>Network Activity</span>
        </div>

        <strong>+{riskBreakdown.network_risk}</strong>
      </div>

      <div className="risk-breakdown-item">
        <div className="breakdown-label">
          <div className="breakdown-icon file-icon">
            <FileWarning size={20} />
          </div>

          <span>File Activity</span>
        </div>

        <strong>+{riskBreakdown.file_risk}</strong>
      </div>

      <div className="risk-breakdown-item">
        <div className="breakdown-label">
          <div className="breakdown-icon system-icon">
            <Server size={20} />
          </div>

          <span>System Anomaly</span>
        </div>

        <strong>+{riskBreakdown.system_risk}</strong>
      </div>

    </div>
  </div>


  {/* Risk Contributors */}
  <div className="risk-panel contributors-panel">

    <div className="panel-header">
      <div>
        <h2>Risk Contributors</h2>
        <p>Activities contributing to the current risk score</p>
      </div>
    </div>


    {/* Suspicious Processes */}

    {suspiciousProcesses.length > 0 && (
      <div className="contributor-category">

        <h3>
          <Cpu size={18} />
          Suspicious Processes
        </h3>

        {suspiciousProcesses.map((process, index) => (
          <div
            className="contributor-item"
            key={`${process.pid}-${index}`}
          >
            <div className="contributor-main">
              <AlertTriangle size={18} />

              <div>
                <strong>{process.name}</strong>

                <p>
                  PID: {process.pid}
                </p>

                <p className="reason-text">
                  {process.reasons?.join(", ")}
                </p>
              </div>
            </div>

            <span className="contributor-score">
              Score: {process.suspicion_score}
            </span>
          </div>
        ))}
      </div>
    )}


    {/* Suspicious Connections */}

    {suspiciousConnections.length > 0 && (
      <div className="contributor-category">

        <h3>
          <Network size={18} />
          Suspicious Network Connections
        </h3>

        {suspiciousConnections.map(
          (connection, index) => (
            <div
              className="contributor-item"
              key={`${connection.pid}-${index}`}
            >
              <div className="contributor-main">
                <AlertTriangle size={18} />

                <div>
                  <strong>
                    {connection.process_name}
                  </strong>

                  <p>
                    {connection.local_address}
                  </p>

                  <p>
                    → {connection.remote_address}
                  </p>

                  <p className="reason-text">
                    {connection.reasons?.join(", ")}
                  </p>
                </div>
              </div>

              <span className="contributor-score">
                Score: {connection.suspicion_score}
              </span>
            </div>
          )
        )}

      </div>
    )}


    {/* Suspicious Files */}

    {suspiciousFiles.length > 0 && (
      <div className="contributor-category">

        <h3>
          <FileWarning size={18} />
          Suspicious File Activity
        </h3>

        {suspiciousFiles.map((file, index) => (
          <div
            className="contributor-item"
            key={index}
          >
            <div className="contributor-main">
              <AlertTriangle size={18} />

              <div>
                <strong>
                  {file.file_path || "Suspicious File"}
                </strong>

                <p className="reason-text">
                  {file.reason || "Suspicious activity detected"}
                </p>
              </div>
            </div>
          </div>
        ))}
      </div>
    )}


    {/* No contributors */}

    {suspiciousProcesses.length === 0 &&
      suspiciousConnections.length === 0 &&
      suspiciousFiles.length === 0 && (
        <div className="no-contributors">
          <ShieldAlert size={28} />
          <p>No suspicious contributors detected.</p>
        </div>
      )}

  </div>

</div>
    </div>
  );
};

export default Dashboard;