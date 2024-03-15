// Copyright 2024 applibrium.com

import { ConfigService } from '@nestjs/config';
import { HealthController } from './health.controller';
import { HealthService } from './health.service';
import { IConfiguration } from '../../models/configuration';

describe('HealthController', () => {
  let healthController: HealthController;
  let healthServiceMock: HealthService;

  beforeEach(() => {
    const configServiceMock = {} as ConfigService<IConfiguration, true>;

    healthServiceMock = new HealthService(configServiceMock);
    healthController = new HealthController(healthServiceMock);
  });

  it('calls health service getHello method', () => {
    const responseMock = { name: 'Hola!' };
    const getHelloSpy = jest
      .spyOn(healthServiceMock, 'getHello')
      .mockReturnValue(responseMock);

    const response = healthController.getHello();

    expect(response).toEqual(responseMock);
    expect(getHelloSpy).toHaveBeenCalledOnceWith();
  });
});
