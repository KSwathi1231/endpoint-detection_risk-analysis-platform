import { useEffect, useState } from "react";
import {
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  Clock,
  Eye,
  X,
  RefreshCw,
} from "lucide-react";

import { getIncidents } from "../services/api";
import "./Incidents.css";

const Incidents = () => {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [error, setError] = useState("");

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      setError("");

      const response = await getIncidents();

      setIncidents(response.data.incidents || []);
    } catch (err) {
      console.error("Error fetching incidents:", err);
      setError("Unable to fetch incidents from the backend.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const totalIncidents = incidents.length;

  const criticalIncidents = incidents.filter(
    (incident) => incident.severity === "CRITICAL"
  ).length;

  const highIncidents = incidents.filter(
    (incident) => incident.severity === "HIGH"
  ).length;

  const openIncidents = incidents.filter(
    (incident) => incident.status === "OPEN"
  ).length;

  const getSeverityClass = (severity) => {
    if (!severity) return "severity-low";

    return `severity-${severity.toLowerCase()}`;
  };

  const formatDate = (dateString) => {
    if (!dateString) return "N/A";

    const date = new Date(dateString);

    return date.toLocaleString();
  };

  return (
    <div className="incidents-page">
      {/* Header */}

      <div className="incidents-header">
        <div>
          <h1>Incident Management</h1>
          <p>
            Monitor and investigate detected security incidents
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={fetchIncidents}
        >
          <RefreshCw size={18} />
          Refresh
        </button>
      </div>

      {/* Summary Cards */}

      <div className="incident-summary-grid">

        <div className="incident-summary-card">
          <div className="summary-icon total-icon">
            <ShieldAlert size={22} />
          </div>

          <div>
            <p>Total Incidents</p>
            <h2>{totalIncidents}</h2>
          </div>
        </div>


        <div className="incident-summary-card">
          <div className="summary-icon critical-icon">
            <AlertTriangle size={22} />
          </div>

          <div>
            <p>Critical</p>
            <h2>{criticalIncidents}</h2>
          </div>
        </div>


        <div className="incident-summary-card">
          <div className="summary-icon high-icon">
            <ShieldAlert size={22} />
          </div>

          <div>
            <p>High Severity</p>
            <h2>{highIncidents}</h2>
          </div>
        </div>


        <div className="incident-summary-card">
          <div className="summary-icon open-icon">
            <Clock size={22} />
          </div>

          <div>
            <p>Open Incidents</p>
            <h2>{openIncidents}</h2>
          </div>
        </div>

      </div>


      {/* Incidents Table */}

      <div className="incidents-container">

        <div className="table-header">
          <div>
            <h2>Detected Incidents</h2>
            <p>
              Security events requiring investigation
            </p>
          </div>
        </div>


        {loading && (
          <div className="loading-state">
            Loading incidents...
          </div>
        )}


        {error && (
          <div className="error-state">
            <AlertTriangle size={22} />
            {error}
          </div>
        )}


        {!loading && !error && incidents.length === 0 && (
          <div className="empty-state">
            <ShieldCheck size={40} />

            <h3>No Security Incidents</h3>

            <p>
              No HIGH or CRITICAL security incidents have been
              detected.
            </p>
          </div>
        )}


        {!loading && !error && incidents.length > 0 && (

          <div className="table-wrapper">

            <table className="incidents-table">

              <thead>
                <tr>
                  <th>Incident ID</th>
                  <th>Severity</th>
                  <th>Risk Score</th>
                  <th>Status</th>
                  <th>Created At</th>
                  <th>Action</th>
                </tr>
              </thead>


              <tbody>

                {incidents.map((incident) => (

                  <tr key={incident.incident_id}>

                    <td className="incident-id">
                      {incident.incident_id
                        ? `${incident.incident_id.slice(0, 8)}...`
                        : "N/A"}
                    </td>


                    <td>
                      <span
                        className={`severity-badge ${getSeverityClass(
                          incident.severity
                        )}`}
                      >
                        {incident.severity || "UNKNOWN"}
                      </span>
                    </td>


                    <td>
                      <span className="risk-score">
                        {incident.risk_score ?? "N/A"}
                      </span>
                    </td>


                    <td>
                      <span className="status-badge">
                        {incident.status || "OPEN"}
                      </span>
                    </td>


                    <td>
                      {formatDate(incident.created_at)}
                    </td>


                    <td>
                      <button
                        className="view-button"
                        onClick={() =>
                          setSelectedIncident(incident)
                        }
                      >
                        <Eye size={16} />
                        View
                      </button>
                    </td>

                  </tr>

                ))}

              </tbody>

            </table>

          </div>
        )}

      </div>


      {/* Incident Details Modal */}

      {selectedIncident && (

        <div className="modal-overlay">

          <div className="incident-modal">

            <div className="modal-header">

              <div>
                <h2>Incident Details</h2>
                <p>
                  Security incident investigation information
                </p>
              </div>

              <button
                className="close-button"
                onClick={() =>
                  setSelectedIncident(null)
                }
              >
                <X size={22} />
              </button>

            </div>


            <div className="incident-details-grid">

              <div className="detail-item">
                <span>Incident ID</span>
                <strong>
                  {selectedIncident.incident_id}
                </strong>
              </div>


              <div className="detail-item">
                <span>Severity</span>
                <strong>
                  {selectedIncident.severity}
                </strong>
              </div>


              <div className="detail-item">
                <span>Risk Score</span>
                <strong>
                  {selectedIncident.risk_score}
                </strong>
              </div>


              <div className="detail-item">
                <span>Status</span>
                <strong>
                  {selectedIncident.status}
                </strong>
              </div>


              <div className="detail-item full-width">
                <span>Created At</span>
                <strong>
                  {formatDate(selectedIncident.created_at)}
                </strong>
              </div>

            </div>


            {/* Recommended Actions */}

            {selectedIncident.recommended_actions?.length > 0 && (

              <div className="recommended-actions">

                <h3>Recommended Actions</h3>

                <ul>
                  {selectedIncident.recommended_actions.map(
                    (action, index) => (
                      <li key={index}>
                        {action}
                      </li>
                    )
                  )}
                </ul>

              </div>

            )}


            {/* Additional Risk Information */}

            <div className="additional-info">

              <div>
                <span>Threat Probability</span>
                <strong>
                  {selectedIncident.threat_probability ?? "N/A"}
                </strong>
              </div>

              <div>
                <span>Anomaly Score</span>
                <strong>
                  {selectedIncident.anomaly_score ?? "N/A"}
                </strong>
              </div>

              <div>
                <span>Response Priority</span>
                <strong>
                  {selectedIncident.response_priority ?? "N/A"}
                </strong>
              </div>

            </div>

          </div>

        </div>

      )}

    </div>
  );
};

export default Incidents;