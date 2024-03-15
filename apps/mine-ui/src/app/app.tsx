// Copyright 2024 applibrium.com

import styled from 'styled-components';
/* import { DashboardScreen } from './screens/dashboard/dashboard.screen'; */
import { Outlet } from 'react-router-dom';
import Root from '../routes/root';
import { IsLoggedIn } from '../service/auth-service';

const StyledApp = styled.div`
  // Your style here
`;

export function App(): JSX.Element {
  return (
    <StyledApp>
      {/*  <DashboardScreen /> */}
      {/*   {location.pathname !== '/' && <Root />} */}
      {/*  <div>{IsLoggedIn('token') ? <Root /> : 'FALSE'}</div> */}
      <Outlet />
    </StyledApp>
  );
}

export default App;
