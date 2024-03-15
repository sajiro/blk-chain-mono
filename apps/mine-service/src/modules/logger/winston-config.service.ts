// Copyright 2024 applibrium.com

import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  WinstonModuleOptions,
  WinstonModuleOptionsFactory,
} from 'nest-winston';
import { IConfiguration } from '../../models/configuration';
import * as winston from 'winston';
import 'winston-daily-rotate-file';
import path from 'path';

@Injectable()
export class WinstonConfigService implements WinstonModuleOptionsFactory {
  constructor(private configService: ConfigService<IConfiguration, true>) {}

  public createWinstonModuleOptions(): WinstonModuleOptions {
    const { printf, combine, timestamp, colorize } = winston.format;

    const logFormat = printf(
      ({ timestamp, context, stack, level, message }) => {
        const stackTrace = context === 'ExceptionsHandler' ? ` (${stack})` : '';
        return `${timestamp} [${
          context || stack[0]
        }] ${level}: ${message}${stackTrace}`;
      }
    );
    const format = combine(timestamp(), logFormat);

    const logFilePath = this.configService.get('logFilePath', { infer: true });

    const maximumFilesToKeep = this.configService.get('logFileMaximum', {
      infer: true,
    });
    const logFileDatePattern = 'YYYY-MM-DD';

    const transports: winston.transport[] = [
      new winston.transports.DailyRotateFile({
        filename: path.join(logFilePath, '%DATE%-error.log'),
        datePattern: logFileDatePattern,
        zippedArchive: false,
        maxFiles: maximumFilesToKeep,
        level: 'error',
      }),
      new winston.transports.DailyRotateFile({
        filename: path.join(logFilePath, '%DATE%-combined.log'),
        datePattern: logFileDatePattern,
        zippedArchive: false,
        maxFiles: maximumFilesToKeep,
      }),
    ];

    if (!this.configService.get('isProduction', { infer: true })) {
      const consoleFormat = combine(
        colorize({ all: true }),
        timestamp(),
        logFormat
      );
      transports.push(
        new winston.transports.Console({ format: consoleFormat })
      );
    }

    return { transports, format };
  }
}
