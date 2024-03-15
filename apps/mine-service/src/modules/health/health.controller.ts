// Copyright 2024 applibrium.com

import { Controller, Get } from '@nestjs/common';
import { HealthService } from './health.service';
import { ApiTags } from '@nestjs/swagger';
import { SkipAuth } from '../auth/skip-auth.decorator';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @SkipAuth()
  @Get('hello')
  public getHello(): object {
    return this.healthService.getHello();
  }
}
