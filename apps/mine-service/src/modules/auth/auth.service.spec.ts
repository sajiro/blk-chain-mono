// Copyright 2024 applibrium.com

import { Model } from 'mongoose';
import { createMock } from '@golevelup/ts-jest';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { user1Mock } from '../users/__mocks__/users.mock';
import { AuthService } from './auth.service';
import { AccessTokenRecord } from './schemas/access-token.schema';
import { AuthTokens } from './models/auth-tokens';
import { IJwtDecodedPayload, IJwtSignPayload } from './models/jwt-payload';
import { IConfiguration } from '../../models/configuration';
import { UserRecord } from '../users/schemas/user.schema';
import { getCurrentUserId } from '../../utils/api.helper';
import { assertUserExists } from '../../assertions/assert-user-exists';
import { assertUserRoleIsAdmin } from '../../assertions/assert-user-role-is-admin';

jest.mock('../../utils/api.helper');
const getCurrentUserIdMock = getCurrentUserId as jest.Mock;

jest.mock('../../assertions/assert-user-exists');
const assertUserExistsMock = assertUserExists as jest.Mock;

jest.mock('../../assertions/assert-user-role-is-admin');
const assertUserRoleIsAdminMock = assertUserRoleIsAdmin as jest.Mock;

describe('AuthService', () => {
  let authService: AuthService;
  let jwtServiceMock: JwtService;
  let configServiceMock: ConfigService<IConfiguration, true>;

  let accessTokenModelMock: Model<AccessTokenRecord>;
  let userModelMock: Model<UserRecord>;

  const deleteManyTokensMock = jest.fn();
  const deleteManyTokensExecMock = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();

    deleteManyTokensMock.mockImplementation(() => ({
      exec: deleteManyTokensExecMock,
    }));

    accessTokenModelMock = createMock<Model<AccessTokenRecord>>();
    accessTokenModelMock.deleteMany = deleteManyTokensMock;

    userModelMock = createMock<Model<UserRecord>>();

    jwtServiceMock = createMock<JwtService>();
    configServiceMock = createMock<ConfigService<IConfiguration, true>>();
    authService = new AuthService(
      jwtServiceMock,
      configServiceMock,
      accessTokenModelMock,
      userModelMock
    );
  });

  describe('signIn', () => {
    const createTokenMock = jest.fn();

    beforeEach(() => {
      jest.clearAllMocks();

      accessTokenModelMock.create = createTokenMock;
    });

    it('returns undefined if email is not found in users list', async () => {
      const findOneSpy = jest
        .spyOn(userModelMock, 'findOne')
        .mockResolvedValue(undefined);

      const accessTokenMock = 'token';

      const signAsyncSpy = jest
        .spyOn(jwtServiceMock, 'signAsync')
        .mockResolvedValue(accessTokenMock);

      const passwordMock = 'password';
      const emailMock = 'Email@Somewhere.COM';

      const response = await authService.signIn(emailMock, passwordMock);

      expect(findOneSpy).toHaveBeenCalledOnceWith({
        email: emailMock.toLowerCase(),
        status: 'enabled',
      });
      expect(signAsyncSpy).not.toHaveBeenCalled();
      expect(response).toBeUndefined();
    });

    it('returns undefined if password is wrong for the given email', async () => {
      const findOneSpy = jest
        .spyOn(userModelMock, 'findOne')
        .mockResolvedValue(user1Mock);

      const accessTokenMock = 'token';

      const signAsyncSpy = jest
        .spyOn(jwtServiceMock, 'signAsync')
        .mockResolvedValue(accessTokenMock);

      const wrongPasswordMock = 'wrong';
      const emailMock = 'EMAIL@somewhere.com';

      const response = await authService.signIn(emailMock, wrongPasswordMock);

      expect(findOneSpy).toHaveBeenCalledOnceWith({
        email: emailMock.toLowerCase(),
        status: 'enabled',
      });
      expect(signAsyncSpy).not.toHaveBeenCalled();
      expect(response).toBeUndefined();
    });

    it('returns access and refresh tokens if email and password combo can be found in users list', async () => {
      jest.spyOn(userModelMock, 'findOne').mockResolvedValue(user1Mock);

      const accessTokenMock = 'access-token';
      const refreshTokenMock = 'refresh-token';

      const signAsyncSpy = jest
        .spyOn(jwtServiceMock, 'signAsync')
        .mockResolvedValueOnce(accessTokenMock)
        .mockResolvedValueOnce(refreshTokenMock);

      const payload = {
        username: user1Mock.email,
        sub: user1Mock._id.toString(),
      };

      const jwtRefreshExpiresInMinutes = 1000;
      const jwtRefreshSecret = 'secret-refresh';

      const configGetSpy = jest
        .spyOn(configServiceMock, 'get')
        .mockReturnValueOnce(jwtRefreshExpiresInMinutes)
        .mockReturnValueOnce(jwtRefreshSecret);

      const passwordMock = 'password';

      const response = await authService.signIn(user1Mock.email, passwordMock);
      const tokenDocMock: AccessTokenRecord = {
        token: accessTokenMock,
        userEmail: user1Mock.email,
      };
      const responseMock: AuthTokens = {
        accessToken: accessTokenMock,
        refreshToken: refreshTokenMock,
      };

      expect(signAsyncSpy).toHaveBeenNthCalledWith(1, payload);
      expect(deleteManyTokensMock).toHaveBeenCalledOnceWith({
        userEmail: user1Mock.email,
      });
      expect(createTokenMock).toHaveBeenCalledOnceWith(tokenDocMock);

      expect(configGetSpy.mock.calls).toEqual([
        ['jwtRefreshExpiresInMinutes', { infer: true }],
        ['jwtRefreshSecret', { infer: true }],
      ]);
      expect(signAsyncSpy).toHaveBeenNthCalledWith(2, payload, {
        secret: jwtRefreshSecret,
        expiresIn: jwtRefreshExpiresInMinutes * 60,
      });

      expect(response).toEqual(responseMock);
    });
  });

  describe('refresh', () => {
    const createTokenMock = jest.fn();

    beforeEach(() => {
      jest.clearAllMocks();

      accessTokenModelMock.create = createTokenMock;
    });

    it('returns undefined if refresh token is invalid', async () => {
      const refreshTokenMock = 'refresh-token';
      const jwtRefreshSecret = 'secret-refresh';

      const configGetSpy = jest
        .spyOn(configServiceMock, 'get')
        .mockReturnValueOnce(jwtRefreshSecret);

      const verifyAsyncSpy = jest
        .spyOn(jwtServiceMock, 'verifyAsync')
        .mockImplementation(() => {
          throw new Error();
        });

      const signAsyncSpy = jest.spyOn(jwtServiceMock, 'signAsync');

      const response = await authService.refresh(refreshTokenMock);

      expect(configGetSpy).toHaveBeenCalledOnceWith('jwtRefreshSecret', {
        infer: true,
      });
      expect(verifyAsyncSpy).toHaveBeenCalledOnceWith(refreshTokenMock, {
        secret: jwtRefreshSecret,
      });
      expect(signAsyncSpy).not.toHaveBeenCalled();
      expect(response).toBeUndefined();
    });

    it('returns access token if a valid refresh token is passed in', async () => {
      const accessTokenMock = 'access-token';
      const refreshTokenMock = 'refresh-token';

      const jwtAccessExpiresInMinutes = 10;
      const jwtRefreshSecret = 'secret-refresh';
      const jwtAccessSecret = 'secret-access';

      const configGetSpy = jest
        .spyOn(configServiceMock, 'get')
        .mockReturnValueOnce(jwtRefreshSecret)
        .mockReturnValueOnce(jwtAccessExpiresInMinutes)
        .mockReturnValueOnce(jwtAccessSecret);

      const refreshPayload: IJwtDecodedPayload = {
        username: user1Mock.email,
        sub: user1Mock._id.toString(),
        iat: 100,
        exp: 200,
      };
      const verifyAsyncSpy = jest
        .spyOn(jwtServiceMock, 'verifyAsync')
        .mockResolvedValueOnce(refreshPayload);

      const accessPayload: IJwtSignPayload = {
        username: user1Mock.email,
        sub: user1Mock._id.toString(),
      };

      const signAsyncSpy = jest
        .spyOn(jwtServiceMock, 'signAsync')
        .mockResolvedValueOnce(accessTokenMock);

      const response = await authService.refresh(refreshTokenMock);

      const tokenDocMock: AccessTokenRecord = {
        token: accessTokenMock,
        userEmail: user1Mock.email,
      };

      expect(configGetSpy.mock.calls).toEqual([
        ['jwtRefreshSecret', { infer: true }],
        ['jwtAccessExpiresInMinutes', { infer: true }],
        ['jwtAccessSecret', { infer: true }],
      ]);
      expect(verifyAsyncSpy).toHaveBeenCalledOnceWith(refreshTokenMock, {
        secret: jwtRefreshSecret,
      });
      expect(signAsyncSpy).toHaveBeenCalledOnceWith(accessPayload, {
        secret: jwtAccessSecret,
        expiresIn: jwtAccessExpiresInMinutes * 60,
      });

      expect(deleteManyTokensMock).toHaveBeenCalledOnceWith({
        userEmail: user1Mock.email,
      });
      expect(createTokenMock).toHaveBeenCalledOnceWith(tokenDocMock);
      expect(response).toEqual(accessTokenMock);
    });
  });

  describe('signOut', () => {
    const findOneTokenMock = jest.fn();
    const findOneTokenExecMock = jest.fn();

    beforeEach(() => {
      jest.clearAllMocks();

      findOneTokenMock.mockImplementation(() => ({
        exec: findOneTokenExecMock,
      }));
      accessTokenModelMock.findOne = findOneTokenMock;
    });

    it('returns undefined if token is not found in whitelist', async () => {
      const tokenMock = 'invalid';
      findOneTokenExecMock.mockResolvedValue(undefined);

      const response = await authService.signOut(tokenMock);

      expect(findOneTokenMock).toHaveBeenCalledOnceWith({ token: tokenMock });
      expect(deleteManyTokensMock).not.toHaveBeenCalled();
      expect(response).toBeUndefined();
    });

    it('deletes token from whitelist if found', async () => {
      const tokenMock = 'token';
      const tokenDocMock: AccessTokenRecord = {
        token: tokenMock,
        userEmail: user1Mock.email,
      };

      findOneTokenExecMock.mockResolvedValue(tokenDocMock);

      const response = await authService.signOut(tokenMock);

      expect(findOneTokenMock).toHaveBeenCalledOnceWith({ token: tokenMock });
      expect(deleteManyTokensMock).toHaveBeenCalledOnceWith({
        token: tokenMock,
      });
      expect(response).toEqual(tokenDocMock);
    });
  });

  describe('ensureCurrentUserIsAdmin', () => {
    it('ensures user has admin role', async () => {
      const userIdMock = 'user-id';
      getCurrentUserIdMock.mockReturnValue(userIdMock);

      const findByIdSpy = jest.spyOn(userModelMock, 'findById');
      findByIdSpy.mockResolvedValue(user1Mock);

      const requestMock = {} as Request;

      await authService.ensureCurrentUserIsAdmin(requestMock);

      expect(getCurrentUserIdMock).toHaveBeenCalledOnceWith(requestMock);
      expect(userModelMock.findById).toHaveBeenCalledOnceWith(userIdMock);
      expect(assertUserExistsMock).toHaveBeenCalledOnceWith(
        user1Mock,
        userIdMock
      );
      expect(assertUserRoleIsAdminMock).toHaveBeenCalledOnceWith(
        user1Mock.role
      );
    });
  });
});
