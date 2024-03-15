// Copyright 2024 applibrium.com

import {
  ValidationArguments,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  registerDecorator,
} from 'class-validator';

@ValidatorConstraint({ name: 'isNotBlankString', async: false })
export class IsNotBlankStringValidator implements ValidatorConstraintInterface {
  public validate(value: string | undefined): boolean {
    return !!value?.trim();
  }

  public defaultMessage({ property }: ValidationArguments): string {
    return `${property} must not be an empty string or only white spaces`;
  }
}

export function IsNotBlankString(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string): void {
    registerDecorator({
      target: object.constructor,
      propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsNotBlankStringValidator,
    });
  };
}
