// Copyright 2024 applibrium.com

import { DeepMocked, createMock } from '@golevelup/ts-jest';
import { AppModule } from './app.module';
import { MiddlewareConsumer } from '@nestjs/common';
import { LoggerMiddleware } from './modules/logger/logger.middleware';
import { MiddlewareConfigProxy } from '@nestjs/common/interfaces';

describe('AppModule', () => {
  let module: AppModule;
  let middlewareConsumerMock: DeepMocked<MiddlewareConsumer>;

  beforeEach(() => {
    jest.resetAllMocks();

    module = new AppModule();
    middlewareConsumerMock = createMock<MiddlewareConsumer>();
  });

  it('applies logger middleware', () => {
    const forRoutesMock = jest.fn();
    const applySpy = jest
      .spyOn(middlewareConsumerMock, 'apply')
      .mockReturnValue({
        forRoutes: forRoutesMock,
      } as unknown as MiddlewareConfigProxy);

    module.configure(middlewareConsumerMock);

    expect(applySpy).toHaveBeenCalledOnceWith(LoggerMiddleware);
    expect(forRoutesMock).toHaveBeenCalledOnceWith('*');
  });
});
