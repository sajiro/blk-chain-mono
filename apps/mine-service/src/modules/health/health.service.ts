// Copyright 2024 applibrium.com

import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { IConfiguration } from '../../models/configuration';

@Injectable()
export class HealthService {
  constructor(private configService: ConfigService<IConfiguration, true>) {}

  public getHello(): object {
    return {
      name: 'MINE API service',
      isProduction: this.configService.get('isProduction'),
    };
  }
}
