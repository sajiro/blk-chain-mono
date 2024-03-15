// Copyright 2024 applibrium.com

import { ApiProperty } from '@nestjs/swagger';
import { ICreateMiningHardwareDto } from '@mine/shared/dtos';
import { IsNotBlankString } from '../../../validators/is-not-blank-string.validator';

export class CreateMiningHardwareDto implements ICreateMiningHardwareDto {
  @ApiProperty({ example: 'name' })
  @IsNotBlankString()
  public readonly name: string;

  @ApiProperty({ example: 'location' })
  @IsNotBlankString()
  public readonly location: string;

  @ApiProperty({ example: 'hashRate' })
  @IsNotBlankString()
  public readonly hashRate: string;
}
