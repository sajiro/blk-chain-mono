// Copyright 2024 applibrium.com

import { ApiProperty } from '@nestjs/swagger';
import { IsOptional } from 'class-validator';
import { IUpdateMiningHardwareDto } from '@mine/shared/dtos';

export class UpdateMiningHardwareDto implements IUpdateMiningHardwareDto {
  @ApiProperty({ example: 'true' })
  @IsOptional()
  public readonly name?: string;

  @ApiProperty({ example: 'true' })
  @IsOptional()
  public readonly location?: string;

  @ApiProperty({ example: 'true' })
  @IsOptional()
  public readonly hashRate?: string;
}
