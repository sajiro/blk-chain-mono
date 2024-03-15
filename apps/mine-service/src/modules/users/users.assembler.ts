// Copyright 2024 applibrium.com

import { Injectable } from '@nestjs/common';
import { UserRecord } from './schemas/user.schema';
import { User, UserRole, UserStatus } from '@mine/shared/models';

@Injectable()
export class UsersAssembler {
  public assembleUser(userRecord: UserRecord): User {
    return {
      id: userRecord._id.toString(),
      firstName: userRecord.firstName,
      lastName: userRecord.lastName,
      email: userRecord.email,
      role: userRecord.role as UserRole,
      status: userRecord.status as UserStatus,
    };
  }
}
