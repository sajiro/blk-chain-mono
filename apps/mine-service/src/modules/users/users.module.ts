// Copyright 2024 applibrium.com

import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { UserRecord, UserSchema } from './schemas/user.schema';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { UsersAssembler } from './users.assembler';
import { AuthModule } from '../auth/auth.module';

@Module({
  exports: [UsersService],
  controllers: [UsersController],
  providers: [UsersService, UsersAssembler],
  imports: [
    MongooseModule.forFeature([{ name: UserRecord.name, schema: UserSchema }]),
    AuthModule,
  ],
})
export class UsersModule {}
