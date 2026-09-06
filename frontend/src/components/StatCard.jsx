import "./StatCard.css";

const StatCard = ({ title, value, subtitle, icon, type }) => {
  return (
    <div className={`stat-card ${type}`}>
      <div className="stat-card-top">
        <div>
          <p className="stat-title">{title}</p>
          <h2 className="stat-value">{value}</h2>
        </div>

        <div className="stat-icon">
          {icon}
        </div>
      </div>

      {subtitle && (
        <p className="stat-subtitle">{subtitle}</p>
      )}
    </div>
  );
};

export default StatCard;