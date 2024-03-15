// Copyright 2024 applibrium.com

import { ConfigService } from '@nestjs/config';
import { IConfiguration } from '../../models/configuration';
import { WinstonConfigService } from './winston-config.service';
import { createMock } from '@golevelup/ts-jest';
import { WinstonModuleOptions } from 'nest-winston';
import * as winston from 'winston';
import 'winston-daily-rotate-file';
import path from 'path';

jest.mock('winston', () => ({
  format: {
    printf: jest.fn(),
    combine: jest.fn(),
    timestamp: jest.fn(),
    colorize: jest.fn(),
  },
  transports: {
    Console: jest.fn(),
    DailyRotateFile: jest.fn(),
  },
}));
jest.mock('winston-daily-rotate-file');

const printfMock = winston.format.printf as jest.Mock;
const combineMock = winston.format.combine as jest.Mock;
const timestampMock = winston.format.timestamp as jest.Mock;
const colorizeMock = winston.format.colorize as jest.Mock;
const ConsoleMock = winston.transports.Console as unknown as jest.Mock;
const DailyRotateFileMock = winston.transports
  .DailyRotateFile as unknown as jest.Mock;

describe('WinstonConfigService', () => {
  let configGetSpy: jest.SpyInstance;
  let service: WinstonConfigService;

  beforeEach(() => {
    jest.clearAllMocks();

    const configServiceMock = createMock<ConfigService<IConfiguration, true>>();
    configGetSpy = jest.spyOn(configServiceMock, 'get');

    service = new WinstonConfigService(configServiceMock);
  });

  describe('log message format', () => {
    it('configures log message format', () => {
      configGetSpy.mockReturnValueOnce('log-file-path');
      configGetSpy.mockReturnValueOnce('log-file-maximum');
      configGetSpy.mockReturnValueOnce(false);

      const formatMock = 'format';
      combineMock.mockReturnValue(formatMock);

      const nowMock = new Date();
      timestampMock.mockReturnValue(nowMock);

      const logFormatMock = 'log-format';
      printfMock.mockReturnValue(logFormatMock);

      const options = service.createWinstonModuleOptions();

      expect(printfMock).toHaveBeenCalledOnceWith(expect.any(Function));

      expect(combineMock).toHaveBeenCalledTimes(2);
      expect(combineMock).toHaveBeenNthCalledWith(1, nowMock, logFormatMock);

      const expectedOptions: WinstonModuleOptions = {
        transports: expect.any(Array),
        format: formatMock as unknown as winston.Logform.Format,
      };
      expect(options).toEqual(expectedOptions);
    });

    it.each([
      ['context', [], 'context', ''],
      [undefined, ['stack-one'], 'stack-one', ''],
      [
        'ExceptionsHandler',
        ['stack-trace'],
        'ExceptionsHandler',
        ' (stack-trace)',
      ],
    ])(
      'builds log format (context: %p, stack: %p)',
      (
        contextMock: string | undefined,
        stackMock: string[],
        expectedContext: string,
        expectedStackTrace: string
      ) => {
        configGetSpy.mockReturnValueOnce('log-file-path');
        configGetSpy.mockReturnValueOnce('log-file-maximum');
        configGetSpy.mockReturnValueOnce(false);

        service.createWinstonModuleOptions();

        expect(printfMock).toHaveBeenCalledOnceWith(expect.any(Function));

        const printfHandler = printfMock.mock.calls[0][0];

        const timestampMock = 'timestamp';
        const levelMock = 'level';
        const messageMock = 'message';

        const logFormat = printfHandler({
          timestamp: timestampMock,
          context: contextMock,
          stack: stackMock,
          level: levelMock,
          message: messageMock,
        });

        expect(logFormat).toEqual(
          `${timestampMock} [${expectedContext}] ${levelMock}: ${messageMock}${expectedStackTrace}`
        );
      }
    );
  });

  describe('transports', () => {
    it.each([[false], [true]])(
      'builds transports (isProduction: %p)',
      (isProductionMock: boolean) => {
        const logFormatMock = 'log-format';
        printfMock.mockReturnValue(logFormatMock);

        const commonFormatMock = 'common-format';
        combineMock.mockReturnValueOnce(commonFormatMock);

        const consoleFormatMock = 'console-format';
        combineMock.mockReturnValueOnce(consoleFormatMock);

        const logFilePathMock = 'log-file-path';
        configGetSpy.mockReturnValueOnce(logFilePathMock);

        const logFileMaximumMock = 'log-file-maximum';
        configGetSpy.mockReturnValueOnce(logFileMaximumMock);

        const errorFileTransportMock = { name: 'error' };
        DailyRotateFileMock.mockReturnValueOnce(errorFileTransportMock);

        const combinedFileTransportMock = { name: 'combined' };
        DailyRotateFileMock.mockReturnValueOnce(combinedFileTransportMock);

        configGetSpy.mockReturnValueOnce(isProductionMock);

        const consoleTransportMock = { name: 'console' };
        ConsoleMock.mockReturnValue(consoleTransportMock);

        const colorizeValueMock = 'colorize';
        colorizeMock.mockReturnValue(colorizeValueMock);

        const nowMock = new Date();
        timestampMock.mockReturnValue(nowMock);

        const options = service.createWinstonModuleOptions();

        expect(printfMock).toHaveBeenCalledOnceWith(expect.any(Function));

        expect(combineMock).toHaveBeenCalledTimes(isProductionMock ? 1 : 2);

        if (!isProductionMock) {
          expect(combineMock).toHaveBeenNthCalledWith(
            2,
            colorizeValueMock,
            nowMock,
            logFormatMock
          );
        }

        expect(configGetSpy).toHaveBeenCalledTimes(3);
        expect(configGetSpy).toHaveBeenNthCalledWith(1, 'logFilePath', {
          infer: true,
        });
        expect(configGetSpy).toHaveBeenNthCalledWith(2, 'logFileMaximum', {
          infer: true,
        });
        expect(configGetSpy).toHaveBeenNthCalledWith(3, 'isProduction', {
          infer: true,
        });

        expect(DailyRotateFileMock).toHaveBeenCalledTimes(2);
        expect(DailyRotateFileMock).toHaveBeenNthCalledWith(1, {
          filename: path.join(logFilePathMock, '%DATE%-error.log'),
          datePattern: 'YYYY-MM-DD',
          zippedArchive: false,
          maxFiles: logFileMaximumMock,
          level: 'error',
        });
        expect(DailyRotateFileMock).toHaveBeenNthCalledWith(2, {
          filename: path.join(logFilePathMock, '%DATE%-combined.log'),
          datePattern: 'YYYY-MM-DD',
          zippedArchive: false,
          maxFiles: logFileMaximumMock,
        });

        if (isProductionMock) {
          expect(ConsoleMock).not.toHaveBeenCalled();
        } else {
          expect(ConsoleMock).toHaveBeenCalledOnceWith({
            format: consoleFormatMock,
          });
        }

        const expectedTransports = [
          errorFileTransportMock,
          combinedFileTransportMock,
        ];
        if (!isProductionMock) {
          expectedTransports.push(consoleTransportMock);
        }

        const expectedOptions = {
          transports: expectedTransports,
          format: commonFormatMock as unknown as winston.Logform.Format,
        } as unknown as WinstonModuleOptions;
        expect(options).toEqual(expectedOptions);
      }
    );
  });
});
