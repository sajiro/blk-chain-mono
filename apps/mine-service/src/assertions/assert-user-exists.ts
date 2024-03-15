// Copyright 2024 applibrium.com

import { UserRecord } from '../modules/users/schemas/user.schema';
import { assertIsDefined } from './assert-is-defined';

export function assertUserExists(
  user: UserRecord | undefined | null,
  userId: string
): asserts user is NonNullable<UserRecord> {
  assertIsDefined(user, `User for id ${userId} not found`);
}
