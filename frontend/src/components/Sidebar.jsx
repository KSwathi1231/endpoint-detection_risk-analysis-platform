import {
  LayoutDashboard,
  ShieldAlert,
  Monitor,
  Activity,
  ShieldCheck
} from "lucide-react";
import { NavLink } from "react-router-dom";

import "./Sidebar.css";

const Sidebar = () => {
  const menuItems = [
    {
      name: "Dashboard",
      path: "/",
      icon: <LayoutDashboard size={20} />
    },
    {
      name: "Incidents",
      path: "/incidents",
      icon: <ShieldAlert size={20} />
    },
    {
      name: "Endpoints",
      path: "/endpoints",
      icon: <Monitor size={20} />
    },
    {
      name: "Threat Analysis",
      path: "/threat-analysis",
      icon: <Activity size={20} />
    }
  ];

  return (
    <aside className="sidebar">
      <div className="logo">
        <ShieldCheck size={30} />
        <div>
          <h2>EndpointGuard</h2>
          <span>AI Security Platform</span>
        </div>
      </div>

      <nav className="nav-menu">
        <p className="menu-title">MAIN MENU</p>

        {menuItems.map((item) => (
          <NavLink
            key={item.name}
            to={item.path}
            className={({ isActive }) =>
              `nav-item ${isActive ? "active" : ""}`
            }
          >
            {item.icon}
            <span>{item.name}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="system-status">
          <span className="status-dot"></span>
          <span>System Protected</span>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;