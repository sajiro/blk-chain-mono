// Copyright 2024 applibrium.com

import { UserRole, UserStatus } from '@mine/shared/models';

export interface ICreateUserDto {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  role: UserRole;
  status: UserStatus;
}
