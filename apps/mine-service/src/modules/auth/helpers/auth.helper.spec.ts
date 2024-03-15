// Copyright 2024 applibrium.com

import { Request } from 'express';
import { createMock } from '@golevelup/ts-jest';
import { refreshTokenCookieName, extractTokenFromHeader } from './auth.helper';

describe('refreshTokenCookieName', () => {
  it('should have the correct value', () => {
    const expectedCookieName = 'jwt_refresh_token';

    expect(refreshTokenCookieName).toEqual(expectedCookieName);
  });
});

describe('extractTokenFromHeader', () => {
  let requestMock: Request;

  beforeEach(() => {
    requestMock = createMock<Request>();
  });

  it('returns Bearer token if request headers contain it', () => {
    const tokenMock = 'token-value';
    requestMock.headers.authorization = 'Bearer ' + tokenMock;

    const result = extractTokenFromHeader(requestMock);

    expect(result).toEqual(tokenMock);
  });
});
