// Copyright 2024 applibrium.com

import { IAccessTokenDto, ISignInDto } from '@mine/shared/dtos';
import { ApiProperty } from '@nestjs/swagger';

export class SignInDto implements ISignInDto {
  @ApiProperty()
  public email: string;

  @ApiProperty()
  public password: string;
}

export class AccessTokenDto implements IAccessTokenDto {
  @ApiProperty()
  public accessToken: string;
}
