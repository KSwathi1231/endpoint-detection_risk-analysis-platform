import { Bell, Search, User } from "lucide-react";

import "./Header.css";

const Header = () => {
  return (
    <header className="header">
      <div className="header-left">
        <h1>Security Operations Center</h1>
        <p>AI-Driven Endpoint Defense Platform</p>
      </div>

      <div className="header-right">
        <div className="search-box">
          <Search size={18} />
          <input
            type="text"
            placeholder="Search incidents..."
          />
        </div>

        <button className="notification-btn">
          <Bell size={20} />
          <span className="notification-dot"></span>
        </button>

        <div className="user-profile">
          <div className="avatar">
            <User size={18} />
          </div>
          <div>
            <strong>Security Admin</strong>
            <p>Administrator</p>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;