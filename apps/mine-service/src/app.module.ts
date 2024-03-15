// Copyright 2024 applibrium.com

import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';
import { HealthModule } from './modules/health/health.module';
import { loadConfig } from './config/load-config';
import { MongooseConfigService } from './db/mongoose-config.service';
import { UserModule } from './modules/user/user.module';
import { LoggerMiddleware } from './modules/logger/logger.middleware';
import { WinstonModule } from 'nest-winston';
import { WinstonConfigService } from './modules/logger/winston-config.service';

import { MiningHardwaresModule } from './modules/mining-hardwares/mining-hardwares.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, load: [loadConfig], cache: true }),
    WinstonModule.forRootAsync({ useClass: WinstonConfigService }),
    MongooseModule.forRootAsync({
      useClass: MongooseConfigService,
    }),
    AuthModule,
    HealthModule,
    UserModule,
    UsersModule,
    MiningHardwaresModule,
  ],
})
export class AppModule implements NestModule {
  public configure(consumer: MiddlewareConsumer): void {
    consumer.apply(LoggerMiddleware).forRoutes('*');
  }
}
