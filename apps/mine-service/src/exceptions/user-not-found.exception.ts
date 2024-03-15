// Copyright 2024 applibrium.com

import { NotFoundException } from '@nestjs/common';

export class UserNotFoundException extends NotFoundException {
  constructor(userId: string) {
    super(`no user found for id '${userId}'`);
  }
}
