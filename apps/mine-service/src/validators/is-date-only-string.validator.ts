// Copyright 2024 applibrium.com

import {
  ValidationArguments,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  isISO8601,
  registerDecorator,
} from 'class-validator';

@ValidatorConstraint({ name: 'isDateOnlyString', async: false })
export class IsDateOnlyStringValidator implements ValidatorConstraintInterface {
  public validate(date: string | undefined): boolean {
    const isFormatValid = !!date?.match(/^\d{4}-\d{2}-\d{2}$/);

    return isFormatValid && isISO8601(date, { strict: true });
  }

  public defaultMessage({ property }: ValidationArguments): string {
    return `${property} must be a valid ISO date (yyyy-mm-dd)`;
  }
}

export function IsDateOnlyString(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string): void {
    registerDecorator({
      target: object.constructor,
      propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsDateOnlyStringValidator,
    });
  };
}
