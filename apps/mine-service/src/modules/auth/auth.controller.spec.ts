// Copyright 2024 applibrium.com

import { Request, Response } from 'express';
import { Model } from 'mongoose';
import {
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { getModelToken } from '@nestjs/mongoose';
import { Test, TestingModule } from '@nestjs/testing';
import { createMock } from '@golevelup/ts-jest';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { SignInDto } from './dtos/auth.dto';
import { AuthTokens } from './models/auth-tokens';
import { user1Mock } from '../users/__mocks__/users.mock';
import { AccessTokenRecord } from './schemas/access-token.schema';
import { refreshTokenCookieName } from './helpers/auth.helper';
import { UserRecord } from '../users/schemas/user.schema';

describe('AuthController', () => {
  let authControllerMock: AuthController;
  let authServiceMock: AuthService;
  let configServiceMock: ConfigService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        AuthService,
        { provide: JwtService, useValue: createMock<JwtService>() },
        { provide: ConfigService, useValue: createMock<ConfigService>() },
        { provide: getModelToken(AccessTokenRecord.name), useValue: Model },
        { provide: getModelToken(UserRecord.name), useValue: Model },
      ],
    }).compile();

    authControllerMock = module.get<AuthController>(AuthController);
    authServiceMock = module.get<AuthService>(AuthService);
    configServiceMock = module.get<ConfigService>(ConfigService);
  });

  describe('signIn', () => {
    it('throws UnauthorizedException if authService.signIn returns undefined', async () => {
      const signInSpy = jest
        .spyOn(authServiceMock, 'signIn')
        .mockResolvedValue(undefined);

      const signInDtoMock: SignInDto = {
        email: 'email',
        password: 'password',
      };

      const resMock = createMock<Response>();

      await expect(async () => {
        return await authControllerMock.signIn(signInDtoMock, resMock);
      }).rejects.toThrowError(UnauthorizedException);

      expect(signInSpy).toHaveBeenCalledOnceWith(
        signInDtoMock.email,
        signInDtoMock.password
      );
    });

    it('returns access token and sets cookie with refresh token if authService.signIn returns those tokens', async () => {
      const accessTokenMock = 'access-token';
      const refreshTokenMock = 'refresh-token';

      const tokensMock: AuthTokens = {
        accessToken: accessTokenMock,
        refreshToken: refreshTokenMock,
      };
      const signInSpy = jest
        .spyOn(authServiceMock, 'signIn')
        .mockResolvedValue(tokensMock);

      const resMock = createMock<Response>();
      const resCookieSpy = jest.spyOn(resMock, 'cookie');

      const useHttpsMock = true;
      const jwtRefreshExpiresInMinutes = 1000;
      const expiresInMilliseconds = jwtRefreshExpiresInMinutes * 60 * 1000;
      const configGetSpy = jest
        .spyOn(configServiceMock, 'get')
        .mockReturnValueOnce(useHttpsMock)
        .mockReturnValueOnce(jwtRefreshExpiresInMinutes);

      const signInDtoMock: SignInDto = {
        email: user1Mock.email,
        password: 'password',
      };
      const response = await authControllerMock.signIn(signInDtoMock, resMock);

      expect(signInSpy).toHaveBeenCalledOnceWith(
        signInDtoMock.email,
        signInDtoMock.password
      );
      expect(configGetSpy).toHaveBeenCalledTimes(2);
      expect(configGetSpy).toHaveBeenNthCalledWith(1, 'useHttps', {
        infer: true,
      });
      expect(configGetSpy).toHaveBeenNthCalledWith(
        2,
        'jwtRefreshExpiresInMinutes',
        { infer: true }
      );
      expect(resCookieSpy).toHaveBeenCalledWith(
        refreshTokenCookieName,
        refreshTokenMock,
        {
          httpOnly: true,
          sameSite: 'none',
          secure: useHttpsMock,
          maxAge: expiresInMilliseconds,
        }
      );
      expect(response).toEqual(
        resMock.json({
          accessToken: accessTokenMock,
        })
      );
    });
  });

  describe('refresh', () => {
    it('throws UnauthorizedException if request does not contain a cookie for refresh token', async () => {
      const reqMock = createMock<Request>();
      const resMock = createMock<Response>();

      const refreshSpy = jest.spyOn(authServiceMock, 'refresh');

      await expect(async () => {
        return await authControllerMock.refresh(reqMock, resMock);
      }).rejects.toThrowError(UnauthorizedException);

      expect(refreshSpy).not.toHaveBeenCalled();
    });

    it('throws UnauthorizedException if authService.refresh returns undefined', async () => {
      const refreshTokenMock = 'refresh-token';
      const reqMock = createMock<Request>();
      reqMock.cookies[refreshTokenCookieName] = refreshTokenMock;

      const resMock = createMock<Response>();

      const refreshSpy = jest
        .spyOn(authServiceMock, 'refresh')
        .mockResolvedValue(undefined);

      await expect(async () => {
        return await authControllerMock.refresh(reqMock, resMock);
      }).rejects.toThrowError(UnauthorizedException);

      expect(refreshSpy).toHaveBeenCalledOnceWith(refreshTokenMock);
    });

    it('returns access token if authService.refresh returns it', async () => {
      const refreshTokenMock = 'refresh-token';
      const reqMock = createMock<Request>();
      reqMock.cookies[refreshTokenCookieName] = refreshTokenMock;

      const accessTokenMock = 'access-token';
      const refreshSpy = jest
        .spyOn(authServiceMock, 'refresh')
        .mockResolvedValue(accessTokenMock);

      const resMock = createMock<Response>();
      const response = await authControllerMock.refresh(reqMock, resMock);

      expect(refreshSpy).toHaveBeenCalledOnceWith(refreshTokenMock);
      expect(response).toEqual(
        resMock.json({
          accessToken: accessTokenMock,
        })
      );
    });
  });

  describe('signOut', () => {
    const requestMock = createMock<Request>();

    it('throws InternalServerErrorException if authService.signOut returns undefined', async () => {
      const signOutSpy = jest
        .spyOn(authServiceMock, 'signOut')
        .mockResolvedValue(undefined);

      const tokenMock = 'token';
      requestMock.headers.authorization = `Bearer ` + tokenMock;

      try {
        await authControllerMock.signOut(requestMock);
        expect.assertions(1);
      } catch (error) {
        expect(error).toBeInstanceOf(InternalServerErrorException);
        expect(error).toEqual(
          new InternalServerErrorException('Unable to delete token')
        );
      }

      expect(signOutSpy).toHaveBeenCalledOnceWith(tokenMock);
    });

    it('returns successfully if authService.signOut returns the deleted token document', async () => {
      const tokenMock = 'token';

      const tokenDocMock: AccessTokenRecord = {
        token: tokenMock,
        userEmail: user1Mock.email,
      };
      const signOutSpy = jest
        .spyOn(authServiceMock, 'signOut')
        .mockResolvedValue(tokenDocMock);

      requestMock.headers.authorization = `Bearer ` + tokenMock;
      await authControllerMock.signOut(requestMock);

      expect(signOutSpy).toHaveBeenCalledOnceWith(tokenMock);
    });
  });
});
