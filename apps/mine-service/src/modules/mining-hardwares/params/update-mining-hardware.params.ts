// Copyright 2024 applibrium.com

import { IsMongoId } from 'class-validator';

export class UpdateMiningHardwareParams {
  @IsMongoId()
  public miningHardwareId: string | undefined;
}
