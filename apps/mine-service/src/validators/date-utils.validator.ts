// Copyright 2024 applibrium.com

import { BadRequestException } from '@nestjs/common';

export class DateUtils {
  public static validateDateRange(startDate: string, endDate: string): void {
    if (new Date(endDate) < new Date(startDate)) {
      throw new BadRequestException('End date must be on or after start date');
    }
  }
}
