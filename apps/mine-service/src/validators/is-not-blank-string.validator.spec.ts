// Copyright 2024 applibrium.com

import { ValidationArguments } from 'class-validator';
import { IsNotBlankStringValidator } from './is-not-blank-string.validator';

describe('IsNotBlankString Validator', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  describe('IsNotBlankStringValidator', () => {
    let constraint: IsNotBlankStringValidator;

    beforeEach(() => {
      constraint = new IsNotBlankStringValidator();
    });

    it.each([
      [undefined, false],
      ['', false],
      ['  ', false],
      ['abc', true],
      [' abc ', true],
      ['a c', true],
    ])(
      'validates string %s',
      (stringMock: string | undefined, isValid: boolean) => {
        expect(constraint.validate(stringMock)).toEqual(isValid);
      }
    );

    it('returns default message', () => {
      const validationArgumentsMock: Partial<ValidationArguments> = {
        property: 'property',
      };
      expect(
        constraint.defaultMessage(
          validationArgumentsMock as ValidationArguments
        )
      ).toEqual(
        `${validationArgumentsMock.property} must not be an empty string or only white spaces`
      );
    });
  });
});
