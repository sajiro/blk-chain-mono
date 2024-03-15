// Copyright 2024 applibrium.com

import { getModelToken } from '@nestjs/mongoose';
import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from './users.service';
import { UserRecord } from './schemas/user.schema';
import { user1Mock } from './__mocks__/users.mock';
import * as bcrypt from 'bcrypt';
import {
  BadRequestException,
  ConflictException,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { ICreateUserDto } from '@mine/shared/dtos';
import { UserStatus } from '@mine/shared/models';

import { assertUserExists } from '../../assertions/assert-user-exists';

jest.mock('bcrypt');

jest.mock('../../assertions/assert-user-exists');
const assertUserExistsMock = assertUserExists as jest.Mock;

describe('UsersService', () => {
 

  let usersService: UsersService;

  type ModelConstructorArgs = Partial<UserRecord>;

  class UserModelMock {
    public static data: ModelConstructorArgs;

    constructor(data: ModelConstructorArgs) {
      UserModelMock.data = data;
    }

    public static find = jest.fn();
    public static findById = jest.fn();
    public static findOne = jest.fn();
    public static updateOne = jest.fn();

    public save(): Promise<{ id: string } | undefined> {
      return Promise.resolve(undefined);
    }
  }

  beforeEach(async () => {
    jest.clearAllMocks();

   

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,

        {
          provide: getModelToken(UserRecord.name),
          useValue: UserModelMock,
        },
      ],
    }).compile();

    usersService = module.get<UsersService>(UsersService);
  });

  describe('createUser', () => {
    const createUserDtoMock: ICreateUserDto = {
      firstName: 'first',
      lastName: 'last',
      email: 'someone@somewhere.com',
      password: 'password',
      role: 'member',
      status: 'enabled',
    };

    it('throws Bad Request if enabled user with email already exists', async () => {
      const foundUserRecordMock: Partial<UserRecord> = {
        email: 'someone@somewhere.com',
      };
      const findOneSpy = jest
        .spyOn(UserModelMock, 'findOne')
        .mockResolvedValue(foundUserRecordMock);

      try {
        await usersService.createUser(createUserDtoMock);
        expect.assertions(1);
      } catch (error) {
        expect(error).toEqual(new ConflictException('User already exists'));
      }

      expect(findOneSpy).toHaveBeenCalledOnceWith({
        email: createUserDtoMock.email.toLowerCase(),
        status: 'enabled',
      });
    });

    it('creates user', async () => {
      const userIdMock = 'user-id';
      const saveSpy = jest
        .spyOn(UserModelMock.prototype, 'save')
        .mockResolvedValue({ id: userIdMock });

      jest.spyOn(UserModelMock, 'findOne').mockResolvedValue(null);

      const passwordHashMock = 'password-hash';
      const hashSpy = jest
        .spyOn(bcrypt, 'hash')
        .mockResolvedValue(passwordHashMock);

      const userId = await usersService.createUser(createUserDtoMock);

      expect(userId).toEqual(userIdMock);
      expect(saveSpy).toHaveBeenCalledOnceWith();

      const { firstName, lastName, email, password, role, status } =
        createUserDtoMock;

      const expectedConstructorArgs: Partial<UserRecord> = {
        firstName,
        lastName,
        email,
        passwordHash: passwordHashMock,
        role,
        status,
      };
      expect(UserModelMock.data).toEqual(expectedConstructorArgs);

      expect(hashSpy).toHaveBeenCalledOnceWith(password, 10);
    });

    it('throws Internal Error if create fails', async () => {
      jest.spyOn(UserModelMock.prototype, 'save').mockResolvedValue(undefined);
      jest.spyOn(UserModelMock, 'findOne').mockResolvedValue(null);

      try {
        await usersService.createUser(createUserDtoMock);
        expect.assertions(1);
      } catch (error) {
        expect(error).toEqual(
          new InternalServerErrorException('Failed to save user')
        );
      }
    });
  });

  describe('updateUserStatus', () => {
    it('throws Not Found if user id not found', async () => {
      const userIdMock = 'user-id';

      const findByIdSpy = jest
        .spyOn(UserModelMock, 'findById')
        .mockResolvedValue(null);

      try {
        await usersService.updateUserStatus(userIdMock, 'disabled');
        expect.assertions(1);
      } catch (error) {
        expect(error).toEqual(
          new NotFoundException(`no user found for id '${userIdMock}'`)
        );
      }

      expect(findByIdSpy).toHaveBeenCalledOnceWith(userIdMock);
    });

    it('updates user status', async () => {
      const userIdMock = 'user-id';
      const statusMock: UserStatus = 'disabled';

      const updateOneMock = jest.fn();
      const userRecordMock = {
        updateOne: updateOneMock,
      };
      const findByIdSpy = jest
        .spyOn(UserModelMock, 'findById')
        .mockResolvedValue(userRecordMock);

      await usersService.updateUserStatus(userIdMock, statusMock);

      const expectedUpdateRecord: Partial<UserRecord> = {
        status: statusMock,
      };
      expect(updateOneMock).toHaveBeenCalledOnceWith(expectedUpdateRecord);
      expect(findByIdSpy).toHaveBeenCalledOnceWith(userIdMock);
    });
  });

  describe('updateUserPassword', () => {
    it('throws Not Found if user id not found', async () => {
      const userIdMock = 'user-id';

      const findByIdSpy = jest
        .spyOn(UserModelMock, 'findById')
        .mockResolvedValue(null);

      try {
        await usersService.updateUserPassword(userIdMock, 'password');
        expect.assertions(1);
      } catch (error) {
        expect(error).toEqual(
          new NotFoundException(`no user found for id '${userIdMock}'`)
        );
      }

      expect(findByIdSpy).toHaveBeenCalledOnceWith(userIdMock);
    });

    it('updates user password', async () => {
      const userIdMock = 'user-id';
      const passwordMock = 'password';

      const updateOneMock = jest.fn();
      const userRecordMock = {
        updateOne: updateOneMock,
      };
      const findByIdSpy = jest
        .spyOn(UserModelMock, 'findById')
        .mockResolvedValue(userRecordMock);

      const passwordHashMock = 'password-hash';
      const hashSpy = jest
        .spyOn(bcrypt, 'hash')
        .mockResolvedValue(passwordHashMock);

      await usersService.updateUserPassword(userIdMock, passwordMock);

      const expectedUpdateRecord: Partial<UserRecord> = {
        passwordHash: passwordHashMock,
      };
      expect(updateOneMock).toHaveBeenCalledOnceWith(expectedUpdateRecord);
      expect(findByIdSpy).toHaveBeenCalledOnceWith(userIdMock);

      expect(hashSpy).toHaveBeenCalledOnceWith(passwordMock, 10);
    });
  });

  describe('changeUserPassword', () => {
    it('asserts user exists', async () => {
      const userIdMock = 'user-id';
      const userMock = { ...user1Mock, save: jest.fn().mockResolvedValue('') };

      const findByIdSpy = jest
        .spyOn(UserModelMock, 'findById')
        .mockResolvedValue(userMock);

      const compareSpy = jest.spyOn(bcrypt, 'compare');
      compareSpy.mockResolvedValue(true);

      await usersService.changeUserPassword(
        userIdMock,
        'current-password',
        'new-password'
      );

      expect(findByIdSpy).toHaveBeenCalledOnceWith(userIdMock);
      expect(assertUserExistsMock).toHaveBeenCalledOnceWith(
        userMock,
        userIdMock
      );
    });

    it('throws Bad Request if the current password is incorrect', async () => {
      const userMock = user1Mock;

      jest.spyOn(UserModelMock, 'findById').mockResolvedValue(userMock);

      const compareSpy = jest.spyOn(bcrypt, 'compare');
      compareSpy.mockResolvedValue(false);

      const currentPasswordMock = 'current-password';
      const newPasswordMock = 'new-password';

      try {
        await usersService.changeUserPassword(
          'user-id',
          currentPasswordMock,
          newPasswordMock
        );
      } catch (error) {
        expect(error).toEqual(
          new BadRequestException('Invalid current password')
        );
      }

      expect(compareSpy).toHaveBeenCalledOnceWith(
        currentPasswordMock,
        userMock.passwordHash
      );
    });

    it('updates user password', async () => {
      const saveMock = jest.fn();
      const userMock = { ...user1Mock, save: saveMock.mockResolvedValue('') };
      const currentPasswordHash = userMock.passwordHash;

      jest.spyOn(UserModelMock, 'findById').mockResolvedValue(userMock);

      const compareSpy = jest.spyOn(bcrypt, 'compare');
      compareSpy.mockResolvedValue(true);

      const hashSpy = jest.spyOn(bcrypt, 'hash');
      const newPasswordHash = 'newPasswordHash';
      hashSpy.mockResolvedValue(newPasswordHash);

      const currentPasswordMock = 'current-password';
      const newPasswordMock = 'new-password';

      await usersService.changeUserPassword(
        'user-id',
        currentPasswordMock,
        newPasswordMock
      );

      expect(compareSpy).toHaveBeenCalledOnceWith(
        currentPasswordMock,
        currentPasswordHash
      );
      expect(hashSpy).toHaveBeenCalledOnceWith(newPasswordMock, 10);

      expect(userMock.passwordHash).toEqual(newPasswordHash);

      expect(saveMock).toHaveBeenCalledOnceWith();
    });
  });
});
