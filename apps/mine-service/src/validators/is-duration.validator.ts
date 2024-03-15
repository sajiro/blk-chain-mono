// Copyright 2024 applibrium.com

import {
  ValidationArguments,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  isInt,
  max,
  min,
  registerDecorator,
} from 'class-validator';

const maxDurationMinutes = 24 * 60;

@ValidatorConstraint({ name: 'isDuration', async: false })
export class IsDurationValidator implements ValidatorConstraintInterface {
  public validate(duration: unknown): boolean {
    return (
      isInt(duration) && min(duration, 0) && max(duration, maxDurationMinutes)
    );
  }

  public defaultMessage({ property }: ValidationArguments): string {
    return `${property} must be numeric and not less than 0 or greater than 24 hours`;
  }
}

export function IsDuration(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string): void {
    registerDecorator({
      target: object.constructor,
      propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsDurationValidator,
    });
  };
}
