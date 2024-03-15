// Copyright 2024 applibrium.com

import { Types } from 'mongoose';
import { UserRecord } from '../schemas/user.schema';

export const user1Mock: UserRecord = {
  _id: new Types.ObjectId('user-0000001'),
  firstName: 'Mary',
  lastName: 'Jane',
  email: 'mary@gmail.com',
  passwordHash: '$2a$10$oBxOUOgqzV7Fw9eeeNcPwObaIcJF2Y91ik3RMAQhbDUOS0Ief7IWS',
  role: 'member',
  status: 'enabled',
};

export const user2Mock: UserRecord = {
  _id: new Types.ObjectId('user-0000002'),
  firstName: 'John',
  lastName: 'Smith',
  email: 'john@gmail.com',
  passwordHash: '$2a$10$oBxOUOgqzV7Fw9eeeNcPwObaIcJF2Y91ik3RMAQhbDUOS0Ief7IWS',
  role: 'member',
  status: 'disabled',
};

export const usersMock: UserRecord[] = [user1Mock, user2Mock];

export const userAdminMock: UserRecord = {
  _id: new Types.ObjectId('user-admin-1'),
  firstName: 'Admin',
  lastName: 'Test',
  email: 'admin@test.com',
  passwordHash: '$2a$10$oBxOUOgqzV7Fw9eeeNcPwObaIcJF2Y91ik3RMAQhbDUOS0Ief7IWS',
  role: 'admin',
  status: 'enabled',
};
