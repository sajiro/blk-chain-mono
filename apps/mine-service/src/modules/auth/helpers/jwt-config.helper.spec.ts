// Copyright 2024 applibrium.com

import { ConfigService } from '@nestjs/config';
import { JwtModuleOptions } from '@nestjs/jwt';
import { configJwtModule } from './jwt-config.helper';
import { createMock } from '@golevelup/ts-jest';
import { IConfiguration } from '../../../models/configuration';

describe('configJwtModule', () => {
  const jwtSecretPath = 'jwtAccessSecret';
  const jwtExpiresInPath = 'jwtAccessExpiresInMinutes';

  let configServiceMock: ConfigService<IConfiguration, true>;

  beforeEach(() => {
    configServiceMock = createMock<ConfigService<IConfiguration, true>>();
  });

  it('configures JwtModule', () => {
    const jwtSecretMock = 'secret_1';
    const jwtExpiresInMock = '100';
    const expiresInSecondsMock = parseInt(jwtExpiresInMock) * 60;

    const getSpy = jest
      .spyOn(configServiceMock, 'get')
      .mockImplementation((path: string) => {
        if (path === jwtSecretPath) {
          return jwtSecretMock;
        } else if (path === jwtExpiresInPath) {
          return jwtExpiresInMock;
        }
      });

    const expectedResult: JwtModuleOptions = {
      global: true,
      secret: jwtSecretMock,
      signOptions: {
        expiresIn: expiresInSecondsMock,
      },
    };
    const result = configJwtModule(configServiceMock);

    expect(getSpy).toHaveBeenCalledTimes(2);
    expect(getSpy).toHaveBeenNthCalledWith(1, jwtExpiresInPath, {
      infer: true,
    });
    expect(getSpy).toHaveBeenNthCalledWith(2, jwtSecretPath, { infer: true });
    expect(result).toEqual(expectedResult);
  });
});
