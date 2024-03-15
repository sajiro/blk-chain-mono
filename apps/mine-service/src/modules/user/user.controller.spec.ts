// Copyright 2024 applibrium.com

import { Request } from 'express';
import { IJwtDecodedPayload } from '../auth/models/jwt-payload';
import { DeepMocked, createMock } from '@golevelup/ts-jest';
import { UserController } from './user.controller';
import { InternalServerErrorException } from '@nestjs/common';
import { User } from '@mine/shared/models';
import { UsersService } from '../users/users.service';
import { UsersAssembler } from '../users/users.assembler';
import { user1Mock } from '../users/__mocks__/users.mock';
import { assertUserExists } from '../../assertions/assert-user-exists';
import { IChangePasswordDto } from '@mine/shared/dtos';

jest.mock('../../assertions/assert-user-exists');
const assertUserExistsMock = assertUserExists as jest.Mock;

describe('UserController', () => {
  let usersServiceMock: DeepMocked<UsersService>;
  let usersAssemblerMock: DeepMocked<UsersAssembler>;

  beforeEach(() => {
    jest.resetAllMocks();

    usersServiceMock = createMock<UsersService>();
    usersAssemblerMock = createMock<UsersAssembler>();
  });

  describe('getUserInformation', () => {
    it('asserts current user exists', async () => {
      const userIdMock = 'user-id';
      const jwtDecodedPayloadMock: Partial<IJwtDecodedPayload> = {
        sub: userIdMock,
      };

      const requestMock = {} as Request;
      requestMock['user'] = jwtDecodedPayloadMock;

      usersServiceMock.findById.mockResolvedValue(user1Mock);

      const controller = new UserController(
        usersServiceMock,
        usersAssemblerMock
      );
      await controller.getUserInformation(requestMock);

      expect(usersServiceMock.findById).toHaveBeenCalledOnceWith(userIdMock);
      expect(assertUserExistsMock).toHaveBeenCalledOnceWith(
        user1Mock,
        userIdMock
      );
    });

    it('returns current user information on success', async () => {
      const jwtDecodedPayloadMock: Partial<IJwtDecodedPayload> = {
        sub: 'user-id',
      };

      const requestMock = {} as Request;
      requestMock['user'] = jwtDecodedPayloadMock;

      const userMock: Partial<User> = {
        email: 'email',
        firstName: 'first-name',
        lastName: 'last-name',
      };

      usersServiceMock.findById.mockResolvedValue(user1Mock);
      usersAssemblerMock.assembleUser.mockReturnValue(userMock as User);

      const controller = new UserController(
        usersServiceMock,
        usersAssemblerMock
      );

      const user = await controller.getUserInformation(requestMock);

      expect(user).toEqual(userMock);
      expect(usersServiceMock.findById).toHaveBeenCalledOnceWith(
        jwtDecodedPayloadMock.sub
      );
    });
  });

  describe('changePassword', () => {
    it('throws an internal error if user not found', async () => {
      const jwtDecodedPayloadMock: Partial<IJwtDecodedPayload> = {
        sub: 'user-id',
      };

      const requestMock = {} as Request;
      requestMock['user'] = jwtDecodedPayloadMock;

      usersServiceMock.changeUserPassword.mockResolvedValue(undefined);

      const controller = new UserController(
        usersServiceMock,
        usersAssemblerMock
      );

      const currentPasswordMock = 'currentPassword';
      const newPasswordMock = 'newPassword';

      const changePasswordDtoMock: IChangePasswordDto = {
        currentPassword: 'currentPassword',
        newPassword: 'newPassword',
      };

      try {
        await controller.changePassword(requestMock, changePasswordDtoMock);
        expect.assertions(1);
      } catch (error) {
        expect(error).toBeInstanceOf(InternalServerErrorException);
        expect(error).toEqual(new InternalServerErrorException());
      }

      expect(usersServiceMock.changeUserPassword).toHaveBeenCalledOnceWith(
        jwtDecodedPayloadMock.sub,
        currentPasswordMock,
        newPasswordMock
      );
    });

    it('should successfully change the user password', async () => {
      const jwtDecodedPayloadMock: Partial<IJwtDecodedPayload> = {
        sub: 'user-id',
      };

      const requestMock = {} as Request;
      requestMock['user'] = jwtDecodedPayloadMock;

      usersServiceMock.changeUserPassword.mockResolvedValue();

      const controller = new UserController(
        usersServiceMock,
        usersAssemblerMock
      );

      const changePasswordMock = 'currentPassword';
      const newPasswordMock = 'newPassword';

      const changePasswordDtoMock: IChangePasswordDto = {
        currentPassword: changePasswordMock,
        newPassword: newPasswordMock,
      };

      const response = await controller.changePassword(
        requestMock,
        changePasswordDtoMock
      );

      expect(response).toEqual(undefined);
      expect(usersServiceMock.changeUserPassword).toHaveBeenCalledOnceWith(
        jwtDecodedPayloadMock.sub,
        changePasswordMock,
        newPasswordMock
      );
    });
  });
});
