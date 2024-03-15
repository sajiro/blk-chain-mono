// Copyright 2024 applibrium.com

import { Link } from 'react-router-dom';
import { GetCurrenData, removeData } from '../service/auth-service';
import { useNavigate } from 'react-router-dom';

export default function Root(): JSX.Element {
  const navigate = useNavigate();

  const handleLogout = (): void => {
    removeData(['token', 'user']);
    navigate('/');
  };

  return (
    <header className="bg-gray-800 text-white p-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-semibold">Bitcoin Mining Dashboard</h2>
        <nav className="space-x-4">
          <Link to="/dashboard" className="text-gray-300 hover:text-white">
            Dashboard
          </Link>
          <Link
            to="/mining-hardware"
            className="text-gray-300 hover:text-white"
          >
            Mining hardware
          </Link>
        </nav>
        <div className="flex items-center space-x-4">
          <p className="text-gray-300">Welcome, {GetCurrenData('user')}</p>
          <button
            onClick={handleLogout}
            className="text-gray-300 hover:text-white focus:outline-none"
          >
            Logout
          </button>
        </div>
      </div>
    </header>
  );
}
