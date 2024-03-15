// Copyright 2024 applibrium.com

import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';

import { UserController } from './user.controller';
import { UsersService } from '../users/users.service';
import { UsersAssembler } from '../users/users.assembler';

import { UserRecord, UserSchema } from '../users/schemas/user.schema';

@Module({
  controllers: [UserController],
  providers: [UsersService, UsersAssembler],
  imports: [
    MongooseModule.forFeature([{ name: UserRecord.name, schema: UserSchema }]),
  ],
})
export class UserModule {}
