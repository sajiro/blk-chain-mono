// Copyright 2024 applibrium.com

import { createMock } from '@golevelup/ts-jest';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { getNewDate } from '@mine/shared/utils/datetime';
import { AuthGuard } from './auth.guard';
import { AuthService } from './auth.service';
import { IConfiguration } from '../../models/configuration';

describe('AuthGuard', () => {
  let authServiceMock: AuthService;
  let configServiceMock: ConfigService<IConfiguration, true>;
  let jwtServiceMock: JwtService;
  let reflectorMock: Reflector;

  let authGuard: AuthGuard;

  let contextMock: ExecutionContext;
  let requestMock: {
    headers: {
      authorization: string;
    };
  };

  const tokenMock = 'token';
  const secretMock = 'secret';

  beforeEach(() => {
    jest.clearAllMocks();

    authServiceMock = createMock<AuthService>();
    configServiceMock = createMock<ConfigService<IConfiguration, true>>();
    jwtServiceMock = createMock<JwtService>();
    reflectorMock = new Reflector();

    authGuard = new AuthGuard(
      authServiceMock,
      configServiceMock,
      jwtServiceMock,
      reflectorMock
    );

    contextMock = createMock<ExecutionContext>();
    requestMock = {
      headers: {
        authorization: `Bearer ${tokenMock}`,
      },
    };
    configServiceMock.get = jest.fn().mockReturnValue(secretMock);

    jwtServiceMock.decode = jest.fn().mockReturnValueOnce({
      exp: getNewDate().getTime() / 1000 + 1000,
    });
  });

  it('should be defined', () => {
    expect(authGuard).toBeDefined();
  });

  it('should return true when SKIP_AUTH_KEY is true', async () => {
    const skipAuthKeyMock = true;

    reflectorMock.getAllAndOverride = jest
      .fn()
      .mockReturnValue(skipAuthKeyMock);

    const canActivate = await authGuard.canActivate(contextMock);

    expect(canActivate).toBe(true);
  });

  it('should return true when SKIP_AUTH_KEY is false and request header contains valid token', async () => {
    const skipAuthKeyMock = false;
    reflectorMock.getAllAndOverride = jest
      .fn()
      .mockReturnValue(skipAuthKeyMock);

    const getRequestMock = jest.fn().mockReturnValue(requestMock);
    const payloadMock = {
      email: 'abc',
    };
    contextMock.switchToHttp = jest.fn().mockReturnValue({
      getRequest: getRequestMock,
    });
    jwtServiceMock.verifyAsync = jest.fn().mockReturnValue(payloadMock);

    const canActivate = await authGuard.canActivate(contextMock);

    expect(contextMock.switchToHttp).toHaveBeenCalledOnce();
    expect(getRequestMock).toHaveBeenCalledOnce();
    expect(configServiceMock.get).toHaveBeenCalledOnceWith('jwtAccessSecret', {
      infer: true,
    });
    expect(jwtServiceMock.verifyAsync).toHaveBeenCalledOnceWith(tokenMock, {
      secret: secretMock,
    });
    expect(canActivate).toBe(true);
  });

  it('should throw UnauthorizedException when SKIP_AUTH_KEY is false and request header contains invalid token', async () => {
    const skipAuthKeyMock = false;
    reflectorMock.getAllAndOverride = jest
      .fn()
      .mockReturnValue(skipAuthKeyMock);

    const getRequestMock = jest.fn().mockReturnValue(requestMock);
    contextMock.switchToHttp = jest.fn().mockReturnValue({
      getRequest: getRequestMock,
    });
    jwtServiceMock.verifyAsync = jest.fn().mockImplementation(() => {
      throw new Error();
    });

    await expect(async () => {
      return await authGuard.canActivate(contextMock);
    }).rejects.toThrowError(UnauthorizedException);

    expect(contextMock.switchToHttp).toHaveBeenCalledOnce();
    expect(getRequestMock).toHaveBeenCalledOnce();
    expect(configServiceMock.get).toHaveBeenCalledOnceWith('jwtAccessSecret', {
      infer: true,
    });
    expect(jwtServiceMock.verifyAsync).toHaveBeenCalledOnceWith(tokenMock, {
      secret: secretMock,
    });
  });

  it('should delete token from whitelist and throw UnauthorizedException when SKIP_AUTH_KEY is false and request header contains expired token', async () => {
    const skipAuthKeyMock = false;
    reflectorMock.getAllAndOverride = jest
      .fn()
      .mockReturnValue(skipAuthKeyMock);

    const getRequestMock = jest.fn().mockReturnValue(requestMock);
    contextMock.switchToHttp = jest.fn().mockReturnValue({
      getRequest: getRequestMock,
    });

    jwtServiceMock.decode = jest.fn().mockReturnValueOnce({
      exp: getNewDate().getTime() / 1000 - 1000,
    });
    jwtServiceMock.verifyAsync = jest.fn();
    authServiceMock.deleteTokenFromWhiteList = jest.fn();

    await expect(async () => {
      return await authGuard.canActivate(contextMock);
    }).rejects.toThrowError(UnauthorizedException);

    expect(contextMock.switchToHttp).toHaveBeenCalledOnce();
    expect(getRequestMock).toHaveBeenCalledOnce();
    expect(jwtServiceMock.decode).toHaveBeenCalledOnceWith(tokenMock);
    expect(authServiceMock.deleteTokenFromWhiteList).toHaveBeenCalledOnceWith(
      tokenMock
    );
    expect(configServiceMock.get).not.toHaveBeenCalledOnce();
    expect(jwtServiceMock.verifyAsync).not.toHaveBeenCalled();
  });

  it('should throw UnauthorizedException when SKIP_AUTH_KEY is false and request header contains no token', async () => {
    const skipAuthKeyMock = false;
    reflectorMock.getAllAndOverride = jest
      .fn()
      .mockReturnValue(skipAuthKeyMock);

    const getRequestMock = jest.fn().mockReturnValue(requestMock);
    requestMock.headers.authorization = 'no token';

    contextMock.switchToHttp = jest.fn().mockReturnValue({
      getRequest: getRequestMock,
    });

    await expect(async () => {
      return await authGuard.canActivate(contextMock);
    }).rejects.toThrowError(UnauthorizedException);

    expect(contextMock.switchToHttp).toHaveBeenCalledOnce();
    expect(getRequestMock).toHaveBeenCalledOnce();
    expect(configServiceMock.get).not.toHaveBeenCalled();
    expect(jwtServiceMock.verifyAsync).not.toHaveBeenCalled();
  });
});
