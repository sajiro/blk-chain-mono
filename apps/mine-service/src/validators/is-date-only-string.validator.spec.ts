// Copyright 2024 applibrium.com

import { ValidationArguments } from 'class-validator';
import { IsDateOnlyStringValidator } from './is-date-only-string.validator';

describe('IsDateOnlyString Validator', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  describe('IsDateOnlyStringValidator', () => {
    let constraint: IsDateOnlyStringValidator;

    beforeEach(() => {
      constraint = new IsDateOnlyStringValidator();
    });

    it.each([
      [undefined, false],
      ['', false],
      ['123', false],
      ['2023-1-11', false],
      ['2023-01-1', false],
      ['2023-02-29', false],
      ['2023-01-01T00:00:00Z', false],
      ['2023-01-01', true],
      ['2024-02-29', true],
    ])(
      'validates date %p',
      (dateMock: string | undefined, isValid: boolean) => {
        expect(constraint.validate(dateMock)).toEqual(isValid);
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
        `${validationArgumentsMock.property} must be a valid ISO date (yyyy-mm-dd)`
      );
    });
  });
});
