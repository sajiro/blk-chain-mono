// Copyright 2024 applibrium.com

import { ConfigService } from '@nestjs/config';
import { MongooseConfigService } from './mongoose-config.service';
import { MongooseModuleOptions } from '@nestjs/mongoose';
import { IConfiguration } from '../models/configuration';

describe('MongooseConfigService', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  it('creates Mongoose module options object', () => {
    const uriMock = 'database-uri';
    const configGetMock = jest.fn().mockReturnValue(uriMock);
    const configServiceMock: Partial<ConfigService<IConfiguration, true>> = {
      get: configGetMock,
    };

    const options = new MongooseConfigService(
      configServiceMock as ConfigService<IConfiguration, true>
    ).createMongooseOptions();

    const expectedOptions: MongooseModuleOptions = {
      uri: uriMock,
    };
    expect(options).toEqual(expectedOptions);

    expect(configGetMock).toHaveBeenCalledOnceWith('databaseUri', {
      infer: true,
    });
  });
});
