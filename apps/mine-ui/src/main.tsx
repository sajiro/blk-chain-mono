// Copyright 2024 applibrium.com

import { StrictMode } from 'react';
import * as ReactDOM from 'react-dom/client';
import './styles.css';
import App from './app/app';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import { createBrowserRouter, RouterProvider } from 'react-router-dom';
/* import Root from './routes/root'; */
import ErrorPage from './app/screens/error.screen';
import LoginPage from './app/screens/login.screen';
import { DashboardScreen } from './app/screens/dashboard/dashboard.screen';
import MiningHardwarePage from './app/screens/mining-hardware.screen';

const queryClient = new QueryClient();

const router = createBrowserRouter([
  {
    path: '/error',
    element: <ErrorPage />,
    errorElement: <ErrorPage />,
  },
  {
    path: '/dashboard',
    element: <DashboardScreen />,
    errorElement: <ErrorPage />,
  },

  {
    path: '/',
    element: <LoginPage />,
    errorElement: <ErrorPage />,
  },

  {
    path: '/mining-hardware',
    element: <MiningHardwarePage />,
    errorElement: <ErrorPage />,
  },
]);

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);
root.render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>
);
