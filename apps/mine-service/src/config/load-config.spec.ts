// Copyright 2024 applibrium.com

import { IConfiguration } from '../models/configuration';
import { loadConfig } from './load-config';

describe('loadConfig', () => {
  const savedEnv = process.env;

  afterEach(() => {
    process.env = savedEnv;
  });

  it('loads configuration from environment variables', () => {
    const envMock = {
      DATABASE_URI: 'host:port/database',
      LOG_FILE_MAXIMUM: 'log-file-maximum',
      LOG_FILE_PATH: 'log-file-path',
      NODE_ENV: 'production',
      JWT_ACCESS_EXPIRES_IN_MINUTES: '100',
      JWT_ACCESS_SECRET: 'jwt-secret-access',
      JWT_REFRESH_EXPIRES_IN_MINUTES: '1000',
      JWT_REFRESH_SECRET: 'jwt-secret-refresh',
      ORGANIZATION_NAME: 'organization-name',
      USE_HTTPS: 'true',
    };
    process.env = envMock;

    const config = loadConfig();

    const expectedConfig: IConfiguration = {
      databaseUri: envMock.DATABASE_URI,
      isProduction: envMock.NODE_ENV === 'production',
      logFileMaximum: envMock.LOG_FILE_MAXIMUM,
      logFilePath: envMock.LOG_FILE_PATH,
      jwtAccessExpiresInMinutes: envMock.JWT_ACCESS_EXPIRES_IN_MINUTES,
      jwtAccessSecret: envMock.JWT_ACCESS_SECRET,
      jwtRefreshExpiresInMinutes: envMock.JWT_REFRESH_EXPIRES_IN_MINUTES,
      jwtRefreshSecret: envMock.JWT_REFRESH_SECRET,
      useHttps: envMock.USE_HTTPS === 'true',
    };

    expect(config).toEqual(expectedConfig);
  });

  it('loads default configuration if missing environment variables', () => {
    process.env = {};

    const config = loadConfig();

    const expectedConfig: IConfiguration = {
      databaseUri: 'mongodb://127.0.0.1:27017/mine',
      isProduction: false,
      logFileMaximum: '30d',
      logFilePath: './logs',
      jwtAccessExpiresInMinutes: '60',
      jwtAccessSecret: 'secret_access',
      jwtRefreshExpiresInMinutes: '1440',
      jwtRefreshSecret: 'secret_refresh',
      useHttps: false,
    };

    expect(config).toEqual(expectedConfig);
  });
});
