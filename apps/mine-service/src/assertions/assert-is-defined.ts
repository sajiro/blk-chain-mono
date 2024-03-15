// Copyright 2024 applibrium.com

import { InternalServerErrorException } from '@nestjs/common';

export function assertIsDefined<T>(
  value: T,
  errorMessage = 'Value is not defined'
): asserts value is NonNullable<T> {
  if (value === undefined || value === null) {
    throw new InternalServerErrorException(errorMessage);
  }
}
