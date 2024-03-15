// Copyright 2024 applibrium.com

import { ApiProperty } from '@nestjs/swagger';
import { IsIn } from 'class-validator';
import { UserStatus, userStatusList } from '@mine/shared/models';
import { IUpdateUserStatusDto } from '@mine/shared/dtos';

export class UpdateUserStatusDto implements IUpdateUserStatusDto {
  @ApiProperty({
    enum: userStatusList,
    example: 'enabled',
  })
  @IsIn(userStatusList)
  public readonly status: UserStatus;
}
