// Copyright 2024 applibrium.com

import { useRouteError } from 'react-router-dom';

export default function ErrorPage(): JSX.Element {
  const error = useRouteError() as Error;

  return (
    <div id="error-page">
      <h1>Oops!</h1>
      <p>Sorry, an unexpected error has occurred. aaaaaa</p>
      <p>
        <i>{error.message ? error.message : error.message}</i>
      </p>
    </div>
  );
}
