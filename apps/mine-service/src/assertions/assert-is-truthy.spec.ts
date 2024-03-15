// Copyright 2024 applibrium.com

import { InternalServerErrorException } from '@nestjs/common';
import { assertIsTruthy } from './assert-is-truthy';

describe('assertIsTruthy', () => {
  it.each([
    [undefined, undefined, true],
    [undefined, 'failed', true],
    [null, undefined, true],
    ['', undefined, true],
    ['x', undefined, false],
  ])(
    'throws error if assertion fails for value %p',
    (
      valueMock: unknown,
      errorMessageMock: string | undefined,
      isErrorExpected: boolean
    ) => {
      try {
        assertIsTruthy(valueMock, errorMessageMock);

        if (isErrorExpected) {
          expect.assertions(1);
        }
      } catch (error) {
        if (!isErrorExpected) {
          expect.assertions(0);
        }

        expect(error).toBeInstanceOf(InternalServerErrorException);
        const expectedError = new InternalServerErrorException(
          errorMessageMock ?? 'Value is falsy'
        );
        expect(error).toEqual(expectedError);
      }
    }
  );
});
