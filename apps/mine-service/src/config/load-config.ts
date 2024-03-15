// Copyright 2024 applibrium.com

import { IConfiguration } from '../models/configuration';

export const loadConfig = (): IConfiguration => {
  const config: IConfiguration = {
    databaseUri: process.env.DATABASE_URI || 'mongodb://127.0.0.1:27017/mine',
    isProduction: process.env.NODE_ENV === 'production',
    logFileMaximum: process.env.LOG_FILE_MAXIMUM || '30d',
    logFilePath: process.env.LOG_FILE_PATH || './logs',
    jwtAccessExpiresInMinutes:
      process.env.JWT_ACCESS_EXPIRES_IN_MINUTES || '60',
    jwtAccessSecret: process.env.JWT_ACCESS_SECRET || 'secret_access',
    jwtRefreshExpiresInMinutes:
      process.env.JWT_REFRESH_EXPIRES_IN_MINUTES || '1440',
    jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || 'secret_refresh',

    useHttps: process.env.USE_HTTPS === 'true',
  };

  return config;
};
