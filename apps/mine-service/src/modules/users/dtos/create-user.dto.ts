// Copyright 2024 applibrium.com

import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsIn } from 'class-validator';
import {
  UserRole,
  UserStatus,
  userRoleList,
  userStatusList,
} from '@mine/shared/models';
import { ICreateUserDto } from '@mine/shared/dtos';
import { IsNotBlankString } from '../../../validators/is-not-blank-string.validator';

export class CreateUserDto implements ICreateUserDto {
  @ApiProperty({ example: 'Jane' })
  @IsNotBlankString()
  public readonly firstName: string;

  @ApiProperty({ example: 'Doe' })
  @IsNotBlankString()
  public readonly lastName: string;

  @ApiProperty({ example: 'jane.doe@somewhere.com' })
  @IsEmail(
    { allow_utf8_local_part: false },
    { message: 'email must be a valid email address' }
  )
  public readonly email: string;

  @ApiProperty({ example: 'password' })
  @IsNotBlankString()
  public readonly password: string;

  @ApiProperty({
    enum: userRoleList,
    example: 'member',
  })
  @IsIn(userRoleList)
  public readonly role: UserRole;

  @ApiProperty({
    enum: userStatusList,
    example: 'enabled',
  })
  @IsIn(userStatusList)
  public readonly status: UserStatus;
}
