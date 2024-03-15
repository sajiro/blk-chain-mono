// Copyright 2024 applibrium.com

import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  MongooseModuleOptions,
  MongooseOptionsFactory,
} from '@nestjs/mongoose';
import { IConfiguration } from '../models/configuration';

@Injectable()
export class MongooseConfigService implements MongooseOptionsFactory {
  constructor(private configService: ConfigService<IConfiguration, true>) {}

  public createMongooseOptions(): MongooseModuleOptions {
    return {
      uri: this.configService.get('databaseUri', { infer: true }),
    };
  }
}
