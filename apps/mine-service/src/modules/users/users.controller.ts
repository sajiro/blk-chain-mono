// Copyright 2024 applibrium.com

import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  Post,
  Put,
  Req,
} from '@nestjs/common';
import { UsersService } from './users.service';
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiInternalServerErrorResponse,
  ApiNoContentResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiParam,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { User } from '@mine/shared/models';
import { UsersAssembler } from './users.assembler';
import { GetUserParams } from './params/get-user.params';
import { CreateUserDto } from './dtos/create-user.dto';
import { UpdateUserStatusDto } from './dtos/update-user-status.dto';
import { ICreatedIdDto } from '@mine/shared/dtos';
import { UpdateUserPasswordDto } from './dtos/update-user-password.dto';
import { AuthService } from '../auth/auth.service';

@ApiTags('Users (Admin)')
@Controller('users')
export class UsersController {
  constructor(
    private usersService: UsersService,
    private usersAssembler: UsersAssembler,
    private authService: AuthService
  ) {}

  @ApiBearerAuth()
  @ApiOkResponse({
    description: 'Success',
    type: User,
    isArray: true,
  })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiForbiddenResponse({ description: 'Forbidden' })
  @Get()
  public async getUsers(@Req() request: Request): Promise<User[]> {
    await this.authService.ensureCurrentUserIsAdmin(request);

    const userRecords = await this.usersService.findAll();
    return userRecords.map((userRecord) =>
      this.usersAssembler.assembleUser(userRecord)
    );
  }

  @ApiBearerAuth()
  @ApiOkResponse({ description: 'Success', type: User })
  @ApiBadRequestResponse({ description: 'Bad request' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiForbiddenResponse({ description: 'Forbidden' })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiParam({ required: true, name: 'userId' })
  @Get(':userId')
  public async getUserById(
    @Req() request: Request,
    @Param() { userId }: GetUserParams
  ): Promise<User | undefined> {
    await this.authService.ensureCurrentUserIsAdmin(request);

    const userRecord = await this.usersService.findById(userId);
    if (!userRecord) {
      throw new NotFoundException();
    }

    return this.usersAssembler.assembleUser(userRecord);
  }

  @ApiBearerAuth()
  @ApiCreatedResponse({ description: 'Created' })
  @ApiBadRequestResponse({ description: 'Bad request' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiForbiddenResponse({ description: "User's role is not 'admin'" })
  @ApiConflictResponse({ description: 'User already exists' })
  @ApiInternalServerErrorResponse({ description: 'Internal error' })
  @Post()
  public async createUser(
    @Req() request: Request,
    @Body() createUserDto: CreateUserDto
  ): Promise<ICreatedIdDto> {
    await this.authService.ensureCurrentUserIsAdmin(request);

    const id = await this.usersService.createUser(createUserDto);
    return { id };
  }

  @ApiBearerAuth()
  @ApiNoContentResponse({ description: 'No content' })
  @ApiBadRequestResponse({ description: 'Bad request' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiForbiddenResponse({ description: "User's role is not 'admin'" })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiInternalServerErrorResponse({ description: 'Internal error' })
  @ApiParam({ required: true, name: 'userId' })
  @HttpCode(HttpStatus.NO_CONTENT)
  @Put(':userId/status')
  public async updateUserStatus(
    @Req() request: Request,
    @Param() { userId }: GetUserParams,
    @Body() { status }: UpdateUserStatusDto
  ): Promise<void> {
    await this.authService.ensureCurrentUserIsAdmin(request);

    await this.usersService.updateUserStatus(userId, status);
  }

  @ApiBearerAuth()
  @ApiNoContentResponse({ description: 'No content' })
  @ApiBadRequestResponse({ description: 'Bad request' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiForbiddenResponse({ description: "User's role is not 'admin'" })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiInternalServerErrorResponse({ description: 'Internal error' })
  @ApiParam({ required: true, name: 'userId' })
  @HttpCode(HttpStatus.NO_CONTENT)
  @Put(':userId/password')
  public async updateUserPassword(
    @Req() request: Request,
    @Param() { userId }: GetUserParams,
    @Body() { password }: UpdateUserPasswordDto
  ): Promise<void> {
    await this.authService.ensureCurrentUserIsAdmin(request);

    await this.usersService.updateUserPassword(userId, password);
  }
}
