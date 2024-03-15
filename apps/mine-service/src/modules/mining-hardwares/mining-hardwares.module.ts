// Copyright 2024 applibrium.com

import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import {
  MiningHardwareSchema,
  MiningHardwareRecord,
} from './schemas/mining-hardware.schema';
import { MiningHardwaresService } from './mining-hardwares.service';
import { MiningHardwaresController } from './mining-hardwares.controller';
import { UserRecord, UserSchema } from '../users/schemas/user.schema';
import { AuthModule } from '../auth/auth.module';

@Module({
  controllers: [MiningHardwaresController],
  providers: [MiningHardwaresService],
  imports: [
    MongooseModule.forFeature([
      { name: MiningHardwareRecord.name, schema: MiningHardwareSchema },
    ]),
    MongooseModule.forFeature([
      {
        name: UserRecord.name,
        schema: UserSchema,
      },
    ]),
    AuthModule,
  ],
})
export class MiningHardwaresModule {}
