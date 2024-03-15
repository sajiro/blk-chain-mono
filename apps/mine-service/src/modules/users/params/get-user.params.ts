// Copyright 2024 applibrium.com

import { IsMongoId } from 'class-validator';

export class GetUserParams {
  @IsMongoId()
  public userId: string;
}
