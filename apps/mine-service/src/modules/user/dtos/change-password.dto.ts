// Copyright 2024 applibrium.com

import { IChangePasswordDto } from '@mine/shared/dtos';
import { IsNotBlankString } from '../../../validators/is-not-blank-string.validator';
import { ApiProperty } from '@nestjs/swagger';

export class ChangePasswordDto implements IChangePasswordDto {
  @ApiProperty()
  @IsNotBlankString()
  public readonly currentPassword: string;

  @ApiProperty()
  @IsNotBlankString()
  public readonly newPassword: string;
}
