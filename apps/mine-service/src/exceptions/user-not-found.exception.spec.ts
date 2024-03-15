// Copyright 2024 applibrium.com

import { NotFoundException } from '@nestjs/common';
import { UserNotFoundException } from './user-not-found.exception';

describe('UserNotFoundException', () => {
  it('constructs exception', () => {
    const userIdMock = 'user-id';
    const exception = new UserNotFoundException(userIdMock);

    expect(exception).toEqual(
      new NotFoundException(`no user found for id '${userIdMock}'`)
    );
  });
});
