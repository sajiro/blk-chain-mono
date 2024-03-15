// Copyright 2024 applibrium.com

import { NestFactory } from '@nestjs/core';
import {
  INestApplication,
  NestApplicationOptions,
  ValidationPipe,
} from '@nestjs/common';
import { AppModule } from './app.module';
import { bootstrap } from './bootstrap';
import { DocumentBuilder, OpenAPIObject, SwaggerModule } from '@nestjs/swagger';
import { createMock } from '@golevelup/ts-jest';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import fs from 'fs';
import { assertIsTruthy } from './assertions/assert-is-truthy';

jest.mock('./assertions/assert-is-truthy');
const assertIsTruthyMock = assertIsTruthy as jest.Mock;

describe('bootstrap', () => {
  const savedEnv = { ...process.env };
  let applicationMock: INestApplication;

  beforeEach(() => {
    jest.resetAllMocks();

    jest
      .spyOn(SwaggerModule, 'createDocument')
      .mockReturnValue({} as OpenAPIObject);
    jest.spyOn(SwaggerModule, 'setup').mockReturnValue(undefined);

    applicationMock = createMock<INestApplication>();
  });

  afterEach(() => {
    process.env = { ...savedEnv };
  });

  it('creates Nest application', async () => {
    const nestFactoryCreateSpy = jest
      .spyOn(NestFactory, 'create')
      .mockResolvedValue(applicationMock);

    await bootstrap();

    expect(nestFactoryCreateSpy).toHaveBeenCalledOnceWith(AppModule, {
      bufferLogs: true,
    });
  });

  it('creates Nest application (https)', async () => {
    const nestFactoryCreateSpy = jest
      .spyOn(NestFactory, 'create')
      .mockResolvedValue(applicationMock);

    const httpsKeyFileMock = 'https-key-file';
    const httpsCertFileMock = 'https-cert-file';

    process.env.USE_HTTPS = 'true';
    process.env.HTTPS_KEY_FILE = httpsKeyFileMock;
    process.env.HTTPS_CERT_FILE = httpsCertFileMock;

    const readFileSyncSpy = jest.spyOn(fs, 'readFileSync');

    const keyMock = 'key';
    readFileSyncSpy.mockReturnValueOnce(keyMock);
    const certMock = 'cert';
    readFileSyncSpy.mockReturnValueOnce(certMock);

    await bootstrap();

    const expectedOptions: NestApplicationOptions = {
      bufferLogs: true,
      httpsOptions: {
        key: keyMock,
        cert: certMock,
      },
    };
    expect(nestFactoryCreateSpy).toHaveBeenCalledOnceWith(
      AppModule,
      expectedOptions
    );

    expect(assertIsTruthyMock).toHaveBeenCalledTimes(2);
    expect(assertIsTruthyMock).toHaveBeenCalledWith(
      httpsKeyFileMock,
      'HTTPS_KEY_FILE variable not defined'
    );
    expect(assertIsTruthyMock).toHaveBeenCalledWith(
      httpsCertFileMock,
      'HTTPS_CERT_FILE variable not defined'
    );

    expect(readFileSyncSpy).toHaveBeenCalledTimes(2);
    expect(readFileSyncSpy).toHaveBeenCalledWith(httpsKeyFileMock);
    expect(readFileSyncSpy).toHaveBeenCalledWith(httpsCertFileMock);
  });

  it('uses Winston logger', async () => {
    jest.spyOn(NestFactory, 'create').mockResolvedValue(applicationMock);

    const winstonProviderMock = jest.fn();
    const appGetSpy = jest
      .spyOn(applicationMock, 'get')
      .mockReturnValue(winstonProviderMock);

    const useLoggerSpy = jest.spyOn(applicationMock, 'useLogger');

    await bootstrap();

    expect(appGetSpy).toHaveBeenCalledOnceWith(WINSTON_MODULE_NEST_PROVIDER);
    expect(useLoggerSpy).toHaveBeenCalledOnceWith(winstonProviderMock);
  });

  it('sets up Swagger documentation', async () => {
    const openApiObjectMock = createMock<OpenAPIObject>();

    jest.spyOn(NestFactory, 'create').mockResolvedValue(applicationMock);

    const setTitleSpy = jest.spyOn(DocumentBuilder.prototype, 'setTitle');
    const setDescriptionSpy = jest.spyOn(
      DocumentBuilder.prototype,
      'setDescription'
    );
    const setVersionSpy = jest.spyOn(DocumentBuilder.prototype, 'setVersion');
    const addTagSpy = jest.spyOn(DocumentBuilder.prototype, 'addTag');
    const addBearerAuthSpy = jest.spyOn(
      DocumentBuilder.prototype,
      'addBearerAuth'
    );

    const configMock = createMock<OpenAPIObject>();
    const buildSpy = jest
      .spyOn(DocumentBuilder.prototype, 'build')
      .mockReturnValue(configMock);

    const createDocumentSpy = jest
      .spyOn(SwaggerModule, 'createDocument')
      .mockReturnValue(openApiObjectMock);
    const setupSpy = jest
      .spyOn(SwaggerModule, 'setup')
      .mockReturnValue(undefined);

    jest.clearAllMocks();

    await bootstrap();

    expect(setTitleSpy).toHaveBeenCalledOnceWith('MINE -- API Documentation');
    expect(setDescriptionSpy).toHaveBeenCalledOnceWith(
      'API documentation for MINE'
    );
    expect(setVersionSpy).toHaveBeenCalledOnceWith('1.0');
    expect(addTagSpy).toHaveBeenCalledOnceWith('mine');
    expect(addBearerAuthSpy).toHaveBeenCalledOnceWith();
    expect(buildSpy).toHaveBeenCalledOnceWith();

    expect(createDocumentSpy).toHaveBeenCalledOnceWith(
      applicationMock,
      configMock
    );
    expect(setupSpy).toHaveBeenCalledOnceWith(
      'api-docs',
      applicationMock,
      openApiObjectMock
    );
  });

  it('enables CORS globally', async () => {
    jest.spyOn(NestFactory, 'create').mockResolvedValue(applicationMock);

    const enableCorsSpy = jest.spyOn(applicationMock, 'enableCors');

    await bootstrap();

    expect(enableCorsSpy).toHaveBeenCalledOnce();
  });

  it('sets cookieParser globally', async () => {
    jest.spyOn(NestFactory, 'create').mockResolvedValue(applicationMock);

    // TODO: figure out a way to test app.use() with cookieParser()
    const useSpy = jest.spyOn(applicationMock, 'use');

    await bootstrap();

    expect(useSpy).toHaveBeenCalledOnce();
  });

  it('sets ValidationPipe globally', async () => {
    jest.spyOn(NestFactory, 'create').mockResolvedValue(applicationMock);

    const useGlobalPipesSpy = jest.spyOn(applicationMock, 'useGlobalPipes');

    await bootstrap();

    expect(useGlobalPipesSpy).toHaveBeenCalledOnceWith(
      expect.any(ValidationPipe)
    );
  });

  it.each([
    [undefined, 3000],
    ['x', 3000],
    ['3001', 3001],
  ])(
    'application listens on configured port %p',
    async (portMock: string | undefined, expectedPort: number) => {
      if (portMock) {
        process.env.PORT = portMock;
      }

      const listenSpy = jest
        .spyOn(applicationMock, 'listen')
        .mockResolvedValue(undefined);

      jest.spyOn(NestFactory, 'create').mockResolvedValue(applicationMock);

      await bootstrap();

      expect(listenSpy).toHaveBeenCalledOnceWith(expectedPort);
    }
  );
});
