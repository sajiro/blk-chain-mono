// Copyright 2024 applibrium.com

import { Body, Controller, Get, Put, Req } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiInternalServerErrorResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { User } from '@mine/shared/models';
import { Request } from 'express';
import { getCurrentUserId } from '../../utils/api.helper';
import { UsersAssembler } from '../users/users.assembler';
import { UsersService } from '../users/users.service';
import { assertUserExists } from '../../assertions/assert-user-exists';
import { ChangePasswordDto } from './dtos/change-password.dto';

@ApiTags('Current user')
@Controller('user')
export class UserController {
  constructor(
    private usersService: UsersService,
    private usersAssembler: UsersAssembler
  ) {}

  @ApiBearerAuth()
  @ApiOkResponse({ description: 'Success', type: User })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiInternalServerErrorResponse({ description: 'Internal error' })
  @Get()
  public async getUserInformation(@Req() request: Request): Promise<User> {
    const userId = getCurrentUserId(request);

    const userRecord = await this.usersService.findById(userId);
    assertUserExists(userRecord, userId);

    return this.usersAssembler.assembleUser(userRecord);
  }

  @ApiBearerAuth()
  @ApiNoContentResponse({ description: 'No content' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiInternalServerErrorResponse({ description: 'Internal error' })
  @Put('password')
  public async changePassword(
    @Req() request: Request,
    @Body() { currentPassword, newPassword }: ChangePasswordDto
  ): Promise<void> {
    const userId = getCurrentUserId(request);

    await this.usersService.changeUserPassword(
      userId,
      currentPassword,
      newPassword
    );
  }
}
