// Copyright 2024 applibrium.com

import { ApiProperty } from '@nestjs/swagger';
import { IMiningHardware } from '@mine/shared/models';

export class MiningHardware implements IMiningHardware {
  @ApiProperty()
  public id: string;

  /*   @ApiProperty()
  public key: string;

  @ApiProperty()
  public value: boolean;

  @ApiProperty()
  public environment: Environment; */

  @ApiProperty()
  public name: string;

  @ApiProperty()
  public location: string;

  @ApiProperty()
  public hashRate: string;
}
