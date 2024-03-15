// Copyright 2024 applibrium.com

export interface IConfiguration {
  databaseUri: string;
  isProduction: boolean;
  logFileMaximum: string; // max log files or age in days (for age, suffix with 'd' -- e.g. '30d')
  logFilePath: string;
  jwtAccessExpiresInMinutes: string;
  jwtAccessSecret: string;
  jwtRefreshExpiresInMinutes: string;
  jwtRefreshSecret: string;
  useHttps: boolean;
}
