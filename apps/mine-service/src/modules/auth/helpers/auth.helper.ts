// Copyright 2024 applibrium.com

import { Request } from 'express';

export const refreshTokenCookieName = 'jwt_refresh_token';

export const extractTokenFromHeader = (
  request: Request
): string | undefined => {
  const [type, token] = request.headers.authorization?.split(' ') ?? [];

  return type === 'Bearer' ? token : undefined;
};
