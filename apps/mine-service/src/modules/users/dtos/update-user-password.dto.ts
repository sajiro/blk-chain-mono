// Copyright 2024 applibrium.com

import { IUpdateUserPasswordDto } from '@mine/shared/dtos';
import { ApiProperty } from '@nestjs/swagger';
import { IsNotBlankString } from '../../../validators/is-not-blank-string.validator';

export class UpdateUserPasswordDto implements IUpdateUserPasswordDto {
  @ApiProperty({ required: true })
  @IsNotBlankString()
  public readonly password: string;
}
