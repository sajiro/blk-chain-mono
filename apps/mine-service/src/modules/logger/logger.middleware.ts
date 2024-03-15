// Copyright 2024 applibrium.com

import {
  HttpStatus,
  Inject,
  Injectable,
  LoggerService,
  NestMiddleware,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';

export interface IErrorResponse {
  statusCode: HttpStatus;
  message?: string | string[];
  error: string;
}

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  constructor(
    @Inject(WINSTON_MODULE_NEST_PROVIDER) private readonly logger: LoggerService
  ) {}

  public use(req: Request, res: Response, next: NextFunction): void {
    const context = 'HTTP';
    const { method, originalUrl, body: requestBody } = req;
    const [oldWrite, oldEnd] = [res.write, res.end];
    const responseBodyBuffer: Buffer[] = [];

    // Response message construction adapted from https://stackoverflow.com/a/58882269/7033700
    (res.write as unknown) = function (chunk, ...args): void {
      responseBodyBuffer.push(Buffer.from(chunk));
      oldWrite.apply(res, [chunk, ...args]);
    };

    res.end = function (chunk, ...args): ReturnType<typeof oldEnd> {
      if (chunk) {
        responseBodyBuffer.push(Buffer.from(chunk));
      }

      return oldEnd.apply(res, [chunk, ...args]);
    };

    res.on('close', () => {
      const { statusCode, statusMessage } = res;

      const maskedBody = this.maskSensitiveProperties(requestBody);
      const formattedMessage = `${method} ${originalUrl}; body: ${JSON.stringify(
        maskedBody
      )} - ${statusCode}, ${statusMessage}`;

      if (statusCode >= 400) {
        const errorMessage = this.buildErrorResponseMessage(responseBodyBuffer);
        this.logger.error(
          errorMessage
            ? `${formattedMessage}; ${errorMessage}`
            : formattedMessage,
          context
        );
      } else {
        this.logger.log(formattedMessage, context);
      }
    });

    next();
  }

  private maskSensitiveProperties(body: object): object {
    const sensitiveProperties = ['password', 'currentPassword', 'newPassword'];

    const maskedBody = { ...body };

    sensitiveProperties.forEach((sensitiveProperty) => {
      if (sensitiveProperty in maskedBody) {
        maskedBody[sensitiveProperty] = '*****';
      }
    });

    return maskedBody;
  }

  private buildErrorResponseMessage(responseBodyBuffer: Buffer[]): string {
    const responseBody = Buffer.concat(responseBodyBuffer).toString('utf8');
    if (!responseBody) {
      return '';
    }

    const bodyObject = JSON.parse(responseBody) as IErrorResponse;
    const message = bodyObject.message || '';

    return Array.isArray(message) ? message.join('; ') : message;
  }
}
