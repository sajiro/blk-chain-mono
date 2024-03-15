// Copyright 2024 applibrium.com

import { InternalServerErrorException } from '@nestjs/common';
import { assertUserExists } from './assert-user-exists';
import { user1Mock } from '../modules/users/__mocks__/users.mock';
import { UserRecord } from '../modules/users/schemas/user.schema';

describe('assertUserExists', () => {
  it.each([
    [undefined, true],
    [undefined, true],
    [null, true],
    [user1Mock, false],
  ])(
    'throws error if assertion fails for value %p',
    (userMock: UserRecord | undefined, isErrorExpected: boolean) => {
      const userIdMock = 'user-id';

      try {
        assertUserExists(userMock, userIdMock);

        if (isErrorExpected) {
          expect.assertions(1);
        }
      } catch (error) {
        if (!isErrorExpected) {
          expect.assertions(0);
        }

        expect(error).toBeInstanceOf(InternalServerErrorException);
        const expectedError = new InternalServerErrorException(
          `User for id ${userIdMock} not found`
        );
        expect(error).toEqual(expectedError);
      }
    }
  );
});
