// Copyright 2024 applibrium.com

import { ValidationArguments } from 'class-validator';
import { IsDurationValidator } from './is-duration.validator';

describe('IsDuration Validator', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  describe('IsDurationValidator', () => {
    let constraint: IsDurationValidator;

    beforeEach(() => {
      constraint = new IsDurationValidator();
    });

    it.each([
      ['', false],
      ['x', false],
      ['0', false],
      ['1', false],
      [-1, false],
      [0, true],
      [1, true],
      [1440, true],
      [1441, false],
    ])('validates duration %p', (durationMock: unknown, isValid: boolean) => {
      expect(constraint.validate(durationMock)).toEqual(isValid);
    });

    it('returns default message', () => {
      const validationArgumentsMock: Partial<ValidationArguments> = {
        property: 'property',
      };
      expect(
        constraint.defaultMessage(
          validationArgumentsMock as ValidationArguments
        )
      ).toEqual(
        `${validationArgumentsMock.property} must be numeric and not less than 0 or greater than 24 hours`
      );
    });
  });
});
