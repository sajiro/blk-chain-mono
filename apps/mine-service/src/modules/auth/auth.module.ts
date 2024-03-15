// Copyright 2024 applibrium.com

import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { MongooseModule } from '@nestjs/mongoose';
import {
  AccessTokenRecord,
  AccessTokenSchema,
} from './schemas/access-token.schema';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { AuthGuard } from './auth.guard';
import { configJwtModule } from './helpers/jwt-config.helper';
import { UserRecord, UserSchema } from '../users/schemas/user.schema';

@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: configJwtModule,
    }),
    MongooseModule.forFeature([
      {
        name: AccessTokenRecord.name,
        schema: AccessTokenSchema,
      },
    ]),
    MongooseModule.forFeature([
      {
        name: UserRecord.name,
        schema: UserSchema,
      },
    ]),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
  ],
  exports: [AuthService],
})
export class AuthModule {}
