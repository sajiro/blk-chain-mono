// Copyright 2024 applibrium.com

import { HttpStatus, LoggerService } from '@nestjs/common';
import { IErrorResponse, LoggerMiddleware } from './logger.middleware';
import { createMock } from '@golevelup/ts-jest';
import { Request, Response } from 'express';

describe('LoggerMiddleware', () => {
  let errorMock: jest.SpyInstance;
  let logMock: jest.SpyInstance;
  let middleware: LoggerMiddleware;

  beforeEach(() => {
    jest.resetAllMocks();

    const loggerServiceMock = createMock<LoggerService>();
    errorMock = jest.spyOn(loggerServiceMock, 'error');
    logMock = jest.spyOn(loggerServiceMock, 'log');

    middleware = new LoggerMiddleware(loggerServiceMock);
  });

  it.each([
    ['log', HttpStatus.OK, undefined, ''],
    ['log', HttpStatus.NO_CONTENT, undefined, ''],
    ['log', HttpStatus.TEMPORARY_REDIRECT, 'ignored', ''],
    [
      'error',
      HttpStatus.BAD_REQUEST,
      'Incorrect request data',
      '; Incorrect request data',
    ],
    ['error', HttpStatus.UNAUTHORIZED, 'Unauthorized', '; Unauthorized'],
    [
      'error',
      HttpStatus.INTERNAL_SERVER_ERROR,
      ['Something unexpected', 'Something worse'],
      '; Something unexpected; Something worse',
    ],
  ])(
    'logs using %p if status code is %p and error message is %p',
    (
      expectedLogMethod: 'error' | 'log',
      statusCodeMock: HttpStatus,
      responseMessageMock: string | string[] | undefined,
      expectedErrorMessage: string
    ) => {
      const requestMock: Request = {
        ...createMock<Request>(),
        method: 'POST',
        originalUrl: 'original-url',
        body: {
          something: 'something',
        },
      };

      const responseOnMock = jest.fn();
      const responseWriteMock = jest.fn();
      const responseEndMock = jest.fn();
      const responseMock: Response = {
        ...createMock<Response>(),
        statusCode: statusCodeMock,
        statusMessage: 'status-message',
        on: responseOnMock,
        write: responseWriteMock,
        end: responseEndMock,
      };

      const nextMock = jest.fn();

      middleware.use(requestMock, responseMock, nextMock);

      if (statusCodeMock >= 400) {
        const errorResponseMock: IErrorResponse = {
          error: 'ignored',
          statusCode: statusCodeMock,
          message: responseMessageMock,
        };
        responseMock.write(JSON.stringify(errorResponseMock));
      }

      expect(responseOnMock).toHaveBeenCalledOnceWith(
        'close',
        expect.any(Function)
      );

      const onHandler = responseOnMock.mock.calls[0][1];
      onHandler();

      const expectedMessage = `${requestMock.method} ${
        requestMock.originalUrl
      }; body: ${JSON.stringify(requestMock.body)} - ${
        responseMock.statusCode
      }, ${responseMock.statusMessage}`;

      if (expectedLogMethod === 'error') {
        expect(errorMock).toHaveBeenCalledOnceWith(
          expectedMessage + expectedErrorMessage,
          'HTTP'
        );
        expect(logMock).not.toHaveBeenCalled();
      } else {
        expect(errorMock).not.toHaveBeenCalled();
        expect(logMock).toHaveBeenCalledOnceWith(expectedMessage, 'HTTP');
      }
    }
  );

  it('masks sensitive body properties', () => {
    const requestMock: Request = {
      ...createMock<Request>(),
      method: 'POST',
      originalUrl: 'original-url',
      body: {
        something: 'something',
        password: 'password',
        newPassword: 'new-password',
        currentPassword: 'current-password',
      },
    };

    const responseOnMock = jest.fn();
    const responseMock: Response = {
      ...createMock<Response>(),
      statusCode: HttpStatus.OK,
      statusMessage: 'status-message',
      on: responseOnMock,
    };

    middleware.use(requestMock, responseMock, jest.fn());

    expect(responseOnMock).toHaveBeenCalledOnce();

    const onHandler = responseOnMock.mock.calls[0][1];
    onHandler();

    const expectedBody = {
      ...requestMock.body,
      password: '*****',
      newPassword: '*****',
      currentPassword: '*****',
    };
    const expectedMessage = `${requestMock.method} ${
      requestMock.originalUrl
    }; body: ${JSON.stringify(expectedBody)} - ${responseMock.statusCode}, ${
      responseMock.statusMessage
    }`;

    expect(logMock).toHaveBeenCalledOnceWith(expectedMessage, 'HTTP');
  });
});
