// Copyright 2024 applibrium.com

import { DeepMocked, createMock } from '@golevelup/ts-jest';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { UserRecord } from './schemas/user.schema';
import { user1Mock, user2Mock } from './__mocks__/users.mock';
import { UsersAssembler } from './users.assembler';
import { User, UserStatus } from '@mine/shared/models';
import {
  ICreateUserDto,
  ICreatedIdDto,
  IUpdateUserPasswordDto,
  IUpdateUserStatusDto,
} from '@mine/shared/dtos';
import { GetUserParams } from './params/get-user.params';
import { AuthService } from '../auth/auth.service';

describe('UsersController', () => {
  let usersController: UsersController;

  let usersServiceMock: DeepMocked<UsersService>;
  let authServiceMock: DeepMocked<AuthService>;
  let usersAssemblerMock: DeepMocked<UsersAssembler>;

  beforeEach(() => {
    jest.resetAllMocks();

    usersServiceMock = createMock<UsersService>();
    authServiceMock = createMock<AuthService>();
    usersAssemblerMock = createMock<UsersAssembler>();

    usersController = new UsersController(
      usersServiceMock,
      usersAssemblerMock,
      authServiceMock
    );
  });

  it('gets all users', async () => {
    const userRecordsMock: UserRecord[] = [user1Mock, user2Mock];
    const findAllSpy = jest
      .spyOn(usersServiceMock, 'findAll')
      .mockResolvedValue(userRecordsMock);

    const expectedUserOne: Partial<User> = {
      firstName: 'first-name-1',
      lastName: 'last-name-1',
    };
    const expectedUserTwo: Partial<User> = {
      firstName: 'first-name-2',
      lastName: 'last-name-2',
    };
    const assembleUserMock = jest.spyOn(usersAssemblerMock, 'assembleUser');
    assembleUserMock.mockReturnValueOnce(expectedUserOne as User);
    assembleUserMock.mockReturnValueOnce(expectedUserTwo as User);

    const requestMock = {} as Request;

    const response = await usersController.getUsers(requestMock);

    expect(response).toEqual([expectedUserOne, expectedUserTwo]);

    expect(authServiceMock.ensureCurrentUserIsAdmin).toHaveBeenCalledOnceWith(
      requestMock
    );
    expect(findAllSpy).toHaveBeenCalledOnceWith();

    expect(assembleUserMock).toHaveBeenCalledTimes(userRecordsMock.length);
    expect(assembleUserMock).toHaveBeenNthCalledWith(1, userRecordsMock[0]);
    expect(assembleUserMock).toHaveBeenNthCalledWith(2, userRecordsMock[1]);
  });

  it('gets user with the given id', async () => {
    const findByIdSpy = jest.spyOn(usersServiceMock, 'findById');

    const userIdMock = user1Mock._id.toString();
    findByIdSpy.mockResolvedValue(user1Mock);

    const expectedUserOne: Partial<User> = {
      firstName: 'first-name-1',
      lastName: 'last-name-1',
    };
    const assembleUserMock = jest.spyOn(usersAssemblerMock, 'assembleUser');
    assembleUserMock.mockReturnValue(expectedUserOne as User);

    const requestMock = {} as Request;

    const response = await usersController.getUserById(requestMock, {
      userId: userIdMock,
    });

    expect(response).toEqual(expectedUserOne);

    expect(authServiceMock.ensureCurrentUserIsAdmin).toHaveBeenCalledOnceWith(
      requestMock
    );

    expect(findByIdSpy).toHaveBeenCalledOnceWith(userIdMock);
    expect(assembleUserMock).toHaveBeenCalledOnceWith(user1Mock);
  });

  it('creates user', async () => {
    const userIdMock = 'user-id';
    const createUserSpy = jest
      .spyOn(usersServiceMock, 'createUser')
      .mockResolvedValue(userIdMock);

    const requestMock = {} as Request;

    const createUserDtoMock: ICreateUserDto = {
      firstName: 'first-name',
      lastName: 'last-name',
      email: 'email',
      password: 'password',
      role: 'member',
      status: 'enabled',
    };
    const response = await usersController.createUser(
      requestMock,
      createUserDtoMock
    );

    const expectedResponse: ICreatedIdDto = {
      id: userIdMock,
    };
    expect(response).toEqual(expectedResponse);

    expect(authServiceMock.ensureCurrentUserIsAdmin).toHaveBeenCalledOnceWith(
      requestMock
    );

    expect(createUserSpy).toHaveBeenCalledOnceWith(createUserDtoMock);
  });

  it('updates user status', async () => {
    const updateUserStatusSpy = jest
      .spyOn(usersServiceMock, 'updateUserStatus')
      .mockResolvedValue();

    const userIdMock = 'user-id';
    const paramsMock: GetUserParams = {
      userId: userIdMock,
    };

    const requestMock = {} as Request;

    const userStatusMock: UserStatus = 'enabled';
    const updateUserStatusDtoMock: IUpdateUserStatusDto = {
      status: userStatusMock,
    };

    await usersController.updateUserStatus(
      requestMock,
      paramsMock,
      updateUserStatusDtoMock
    );

    expect(authServiceMock.ensureCurrentUserIsAdmin).toHaveBeenCalledOnceWith(
      requestMock
    );

    expect(updateUserStatusSpy).toHaveBeenCalledOnceWith(
      userIdMock,
      userStatusMock
    );
  });

  it('updates user password', async () => {
    const updateUserPasswordSpy = jest
      .spyOn(usersServiceMock, 'updateUserPassword')
      .mockResolvedValue();

    const userIdMock = 'user-id';
    const paramsMock: GetUserParams = {
      userId: userIdMock,
    };

    const requestMock = {} as Request;

    const userPasswordMock = 'password';
    const updateUserPasswordDtoMock: IUpdateUserPasswordDto = {
      password: userPasswordMock,
    };

    await usersController.updateUserPassword(
      requestMock,
      paramsMock,
      updateUserPasswordDtoMock
    );

    expect(authServiceMock.ensureCurrentUserIsAdmin).toHaveBeenCalledOnceWith(
      requestMock
    );

    expect(updateUserPasswordSpy).toHaveBeenCalledOnceWith(
      userIdMock,
      userPasswordMock
    );
  });
});
