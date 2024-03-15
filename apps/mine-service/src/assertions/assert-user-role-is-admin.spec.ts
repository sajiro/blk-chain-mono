// Copyright 2024 applibrium.com

import { ForbiddenException } from '@nestjs/common';
import {
  userAdminMock,
  user1Mock,
} from '../modules/users/__mocks__/users.mock';
import { assertUserRoleIsAdmin } from './assert-user-role-is-admin';

describe('assertUserRoleIsAdmin', () => {
  it("throws error if user's role is not 'admin'", () => {
    const expectedError = new ForbiddenException("User's role is not 'admin'");

    expect(() => {
      assertUserRoleIsAdmin(user1Mock.role);
    }).toThrow(expectedError);
  });

  it("does not throw error if user's role is 'admin'", () => {
    expect(() => {
      assertUserRoleIsAdmin(userAdminMock.role);
    }).not.toThrow();
  });
});
