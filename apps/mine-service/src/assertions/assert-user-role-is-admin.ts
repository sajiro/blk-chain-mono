// Copyright 2024 applibrium.com

import { ForbiddenException } from '@nestjs/common';
import { UserRole } from '@mine/shared/models';

export function assertUserRoleIsAdmin(
  userRole: UserRole
): asserts userRole is 'admin' {
  const errorMessage = "User's role is not 'admin'";

  if (userRole !== 'admin') {
    throw new ForbiddenException(errorMessage);
  }
}
