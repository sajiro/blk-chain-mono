// Copyright 2024 applibrium.com

import { IsMongoId } from 'class-validator';

export class DeleteMiningHardwareParams {
  @IsMongoId()
  public miningHardwareId: string;
}
