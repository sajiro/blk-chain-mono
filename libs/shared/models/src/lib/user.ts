// Copyright 2024 applibrium.com

import { ApiProperty } from '@nestjs/swagger';

export const userRoleList = ['admin', 'member'] as const;
export type UserRole = (typeof userRoleList)[number];

export const userStatusList = ['enabled', 'disabled'] as const;
export type UserStatus = (typeof userStatusList)[number];

// TODO: Define interface here and remove NestJs decorators (shouldn't be
// in code used directly in UI)

export class AssignedClient {
  @ApiProperty()
  public id: string;

  @ApiProperty()
  public name: string;
}

export class AssignedProject {
  @ApiProperty()
  public id: string;

  @ApiProperty()
  public name: string;
}

export class AssignedActivity {
  @ApiProperty()
  public id: string;

  @ApiProperty()
  public name: string;
}

export class User {
  @ApiProperty()
  public id: string;

  @ApiProperty()
  public firstName: string;

  @ApiProperty()
  public lastName: string;

  @ApiProperty()
  public email: string;

  @ApiProperty({
    enum: ['admin', 'manager', 'member'],
    example: 'member',
  })
  public role: UserRole;

  @ApiProperty({
    enum: ['enabled', 'disabled'],
    example: 'enabled',
  })
  public status: UserStatus;
}
