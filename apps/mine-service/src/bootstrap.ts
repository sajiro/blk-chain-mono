// Copyright 2024 applibrium.com

import cookieParser from 'cookie-parser';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';
import {
  INestApplication,
  NestApplicationOptions,
  ValidationPipe,
} from '@nestjs/common';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { HttpsOptions } from '@nestjs/common/interfaces/external/https-options.interface';
import { readFileSync } from 'fs';
import { assertIsTruthy } from './assertions/assert-is-truthy';
import {
  getBooleanEnvironmentVariable,
  getIntegerEnvironmentVariable,
  getStringEnvironmentVariable,
} from './utils/env/env.helper';

export async function bootstrap(): Promise<void> {
  const app = await createApp();

  app.useLogger(app.get(WINSTON_MODULE_NEST_PROVIDER));

  const config = new DocumentBuilder()
    .setTitle('MINE -- API Documentation')
    .setDescription('API documentation for MINE')
    .setVersion('1.0')
    .addTag('mine')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api-docs', app, document);

  app.enableCors();
  app.use(cookieParser());
  app.useGlobalPipes(new ValidationPipe());

  const port = getIntegerEnvironmentVariable('PORT', 3000);
  await app.listen(port);
}

const createApp = async (): Promise<INestApplication> => {
  const useHttps = getBooleanEnvironmentVariable('USE_HTTPS');

  if (useHttps) {
    const keyFile = getStringEnvironmentVariable('HTTPS_KEY_FILE');
    assertIsTruthy(keyFile, 'HTTPS_KEY_FILE variable not defined');

    const certFile = getStringEnvironmentVariable('HTTPS_CERT_FILE');
    assertIsTruthy(certFile, 'HTTPS_CERT_FILE variable not defined');

    const httpsOptions: HttpsOptions = {
      key: readFileSync(keyFile),
      cert: readFileSync(certFile),
    };
    const applicationOptions: NestApplicationOptions = {
      bufferLogs: true,
      httpsOptions,
    };

    return await NestFactory.create(AppModule, applicationOptions);
  }

  return await NestFactory.create(AppModule, {
    bufferLogs: true,
  });
};
