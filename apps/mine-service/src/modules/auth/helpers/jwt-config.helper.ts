// Copyright 2024 applibrium.com

import { ConfigService } from '@nestjs/config';
import { JwtModuleOptions } from '@nestjs/jwt';
import { IConfiguration } from '../../../models/configuration';

export const configJwtModule = (
  configService: ConfigService<IConfiguration, true>
): JwtModuleOptions => {
  const expiresInSeconds =
    parseInt(configService.get('jwtAccessExpiresInMinutes', { infer: true })) *
    60;

  return {
    global: true,
    secret: configService.get('jwtAccessSecret', { infer: true }),
    signOptions: {
      expiresIn: expiresInSeconds,
    },
  };
};
