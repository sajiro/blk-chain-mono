// Copyright 2024 applibrium.com

import { Test, TestingModule } from '@nestjs/testing';
import { HealthService } from './health.service';
import { ConfigService } from '@nestjs/config';

describe('HealthService', () => {
  let healthService: HealthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [],
      providers: [ConfigService, HealthService],
    }).compile();

    healthService = module.get<HealthService>(HealthService);
  });

  it('handles getHello request', () => {
    const configGetSpy = jest.spyOn(ConfigService.prototype, 'get');

    const isProductionMock = true;
    configGetSpy.mockReturnValueOnce(isProductionMock);

    const response = healthService.getHello();

    const expected = {
      name: 'MINE API service',
      isProduction: isProductionMock,
    };
    expect(response).toEqual(expected);

    expect(configGetSpy).toHaveBeenCalledTimes(2);
    expect(configGetSpy).toHaveBeenNthCalledWith(1, 'isProduction');
    expect(configGetSpy).toHaveBeenNthCalledWith(2, 'organization', {
      infer: true,
    });
  });
});
