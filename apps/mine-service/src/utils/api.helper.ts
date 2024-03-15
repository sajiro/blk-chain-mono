// Copyright 2024 applibrium.com

import { Request as ExpressRequest } from 'express';
import { IJwtDecodedPayload } from '../modules/auth/models/jwt-payload';

export const getCurrentUserId = (request: Request | ExpressRequest): string => {
  const decodedToken = request['user'] as IJwtDecodedPayload;
  return decodedToken.sub;
};
