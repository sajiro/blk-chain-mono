// Copyright 2024 applibrium.com

import { IJwtDecodedPayload } from '../modules/auth/models/jwt-payload';
import { getCurrentUserId } from './api.helper';

describe('apiHelper', () => {
  const currentUserIdMock = 'current-user-id';
  const requestMock = {} as Request;

  beforeEach(() => {
    jest.resetAllMocks();
  });

  describe('getCurrentUserId', () => {
    it('extracts current user id from JWT token', () => {
      const jwtDecodedPayloadMock: Partial<IJwtDecodedPayload> = {
        sub: currentUserIdMock,
      };
      requestMock['user'] = jwtDecodedPayloadMock;

      expect(getCurrentUserId(requestMock)).toEqual(currentUserIdMock);
    });
  });
});
