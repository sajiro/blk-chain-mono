// Copyright 2024 applibrium.com

import { InternalServerErrorException } from '@nestjs/common';

export function assertIsTruthy<T>(
  value: T,
  errorMessage = 'Value is falsy'
): asserts value is NonNullable<T> {
  if (!value) {
    throw new InternalServerErrorException(errorMessage);
  }
}
