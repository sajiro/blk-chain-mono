// Copyright 2024 applibrium.com

import { BadRequestException } from '@nestjs/common';
import { DateUtils } from './date-utils.validator';

describe('DateUtils', () => {
  describe('validateDateRange', () => {
    it('doesnt throw an error when end date is after start date', () => {
      const startDate = '2023-08-01';
      const endDate = '2023-08-15';

      expect(() =>
        DateUtils.validateDateRange(startDate, endDate)
      ).not.toThrow();
    });

    it('throws a BadRequestException when end date is before start date', () => {
      const startDate = '2023-08-15';
      const endDate = '2023-08-01';

      expect(() => DateUtils.validateDateRange(startDate, endDate)).toThrow(
        new BadRequestException('End date must be on or after start date')
      );
    });
  });
});
