import { useEffect, useState } from "react";
import {
  Monitor,
  ShieldCheck,
  Activity,
  Network,
  Cpu,
  Clock,
  RefreshCw,
  AlertTriangle,
  Server,
} from "lucide-react";

import { getLatestEndpoint } from "../services/api";
import "./Endpoints.css";

const Endpoints = () => {
  const [endpointData, setEndpointData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchEndpointData = async () => {
    try {
      setLoading(true);
      setError("");

      const response = await getLatestEndpoint();

      setEndpointData(response.data.endpoint_analysis);
    } catch (err) {
      console.error("Error fetching endpoint data:", err);
      setError("Unable to fetch endpoint information.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEndpointData();
  }, []);

  const formatDate = (dateString) => {
    if (!dateString) return "N/A";

    return new Date(dateString).toLocaleString();
  };

  const getSeverityClass = (severity) => {
    if (!severity) return "low";

    return severity.toLowerCase();
  };

  if (loading) {
    return (
      <div className="endpoints-page loading-page">
        Loading endpoint information...
      </div>
    );
  }

  if (error) {
    return (
      <div className="endpoints-page">
        <div className="endpoint-error">
          <AlertTriangle size={22} />
          {error}
        </div>
      </div>
    );
  }

  const endpointInfo = endpointData?.endpoint_info || {};

  const processData =
    endpointData?.risk_contributors?.suspicious_processes || [];

  const networkData =
    endpointData?.risk_contributors?.suspicious_connections || [];

  return (
    <div className="endpoints-page">

      {/* Header */}

      <div className="endpoints-header">
        <div>
          <h1>Endpoint Management</h1>
          <p>
            Monitor and manage protected devices in your security environment
          </p>
        </div>

        <button
          className="refresh-endpoint-button"
          onClick={fetchEndpointData}
        >
          <RefreshCw size={17} />
          Refresh
        </button>
      </div>


      {/* Endpoint Main Card */}

      <div className="endpoint-main-card">

        <div className="endpoint-main-top">

          <div className="endpoint-title-section">

            <div className="endpoint-device-icon">
              <Monitor size={30} />
            </div>

            <div>
              <h2>
                {endpointInfo.hostname || "Unknown Endpoint"}
              </h2>

              <p>
                {endpointInfo.operating_system || "Unknown OS"}
              </p>
            </div>

          </div>


          <div className="endpoint-active-status">
            <span className="active-dot"></span>
            ACTIVE
          </div>

        </div>


        <div className="endpoint-info-grid">

          <div className="endpoint-info-item">
            <Server size={18} />

            <div>
              <span>Endpoint ID</span>
              <strong>
                {endpointInfo.endpoint_id
                  ? `${endpointInfo.endpoint_id.slice(0, 18)}...`
                  : "N/A"}
              </strong>
            </div>
          </div>


          <div className="endpoint-info-item">
            <Monitor size={18} />

            <div>
              <span>Operating System</span>
              <strong>
                {endpointInfo.operating_system || "N/A"}
              </strong>
            </div>
          </div>


          <div className="endpoint-info-item">
            <Cpu size={18} />

            <div>
              <span>Architecture</span>
              <strong>
                {endpointInfo.architecture || "N/A"}
              </strong>
            </div>
          </div>


          <div className="endpoint-info-item">
            <Network size={18} />

            <div>
              <span>IP Address</span>
              <strong>
                {endpointInfo.ip_address || "N/A"}
              </strong>
            </div>
          </div>


          <div className="endpoint-info-item">
            <Activity size={18} />

            <div>
              <span>OS Version</span>
              <strong className="version-text">
                {endpointInfo.os_version || "N/A"}
              </strong>
            </div>
          </div>


          <div className="endpoint-info-item">
            <Clock size={18} />

            <div>
              <span>Last Telemetry</span>
              <strong>
                {formatDate(endpointData?.telemetry_timestamp)}
              </strong>
            </div>
          </div>

        </div>

      </div>


      {/* Security Status */}

      <div className="endpoint-section-header">
        <h2>Current Security Status</h2>
        <p>Latest security analysis for this endpoint</p>
      </div>


      <div className="endpoint-security-grid">

        <div className="security-stat-card">
          <div className="security-icon risk-icon">
            <ShieldCheck size={22} />
          </div>

          <div>
            <p>Risk Score</p>
            <h2>
              {endpointData?.risk_score ?? 0}
            </h2>
          </div>
        </div>


        <div className="security-stat-card">
          <div className="security-icon severity-icon">
            <AlertTriangle size={22} />
          </div>

          <div>
            <p>Severity</p>

            <span
              className={`endpoint-severity ${getSeverityClass(
                endpointData?.severity
              )}`}
            >
              {endpointData?.severity || "LOW"}
            </span>
          </div>
        </div>


        <div className="security-stat-card">
          <div className="security-icon process-icon">
            <Activity size={22} />
          </div>

          <div>
            <p>Suspicious Processes</p>
            <h2>{processData.length}</h2>
          </div>
        </div>


        <div className="security-stat-card">
          <div className="security-icon network-icon">
            <Network size={22} />
          </div>

          <div>
            <p>Suspicious Connections</p>
            <h2>{networkData.length}</h2>
          </div>
        </div>

      </div>


      {/* Monitoring Components */}

      <div className="monitoring-section">

        <div className="endpoint-section-header">
          <h2>Monitoring Components</h2>
          <p>Security services currently monitoring this endpoint</p>
        </div>


        <div className="monitoring-grid">

          <div className="monitor-card">
            <Activity size={24} />

            <div>
              <h3>Process Monitor</h3>
              <p>Monitoring running processes</p>
            </div>

            <span className="component-active">
              ACTIVE
            </span>
          </div>


          <div className="monitor-card">
            <Network size={24} />

            <div>
              <h3>Network Monitor</h3>
              <p>Monitoring network connections</p>
            </div>

            <span className="component-active">
              ACTIVE
            </span>
          </div>


          <div className="monitor-card">
            <Cpu size={24} />

            <div>
              <h3>System Monitor</h3>
              <p>Monitoring system anomalies</p>
            </div>

            <span className="component-active">
              ACTIVE
            </span>
          </div>


          <div className="monitor-card">
            <ShieldCheck size={24} />

            <div>
              <h3>File Monitor</h3>
              <p>Monitoring file system activity</p>
            </div>

            <span className="component-active">
              ACTIVE
            </span>
          </div>

        </div>

      </div>

    </div>
  );
};

export default Endpoints;