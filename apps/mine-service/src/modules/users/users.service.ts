// Copyright 2024 applibrium.com

import {
  BadRequestException,
  ConflictException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { UserRecord } from './schemas/user.schema';
import * as bcrypt from 'bcrypt';
import { assertUserExists } from '../../assertions/assert-user-exists';
import { CreateUserDto } from './dtos/create-user.dto';
import { UserStatus } from '@mine/shared/models';
import { UserNotFoundException } from '../../exceptions/user-not-found.exception';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(UserRecord.name) private userModel: Model<UserRecord>
  ) {}

  public async findAll(): Promise<UserRecord[]> {
    const findAll = this.userModel.find();
    return (await this.populateAndExecuteQuery(findAll)) ?? [];
  }

  public async findById(id: string): Promise<UserRecord | undefined> {
    const findById = this.userModel.findById(id);
    return (await this.populateAndExecuteQuery(findById)) ?? undefined;
  }

  public async findByEmail(email: string): Promise<UserRecord | undefined> {
    const findByEmail = this.findEnabledUserByEmail(email);
    return await this.populateAndExecuteQuery(findByEmail);
  }

  public async createUser(createUserDto: CreateUserDto): Promise<string> {
    const { firstName, lastName, email, password, role, status } =
      createUserDto;

    const existingUserRecord = await this.findEnabledUserByEmail(email);
    if (existingUserRecord) {
      throw new ConflictException('User already exists');
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const userModel = new this.userModel({
      firstName,
      lastName,
      email,
      passwordHash,
      role,
      status,
    });

    const userId = (await userModel.save())?.id;
    if (!userId) {
      throw new InternalServerErrorException('Failed to save user');
    }

    return userId;
  }

  public async updateUserStatus(
    userId: string,
    status: UserStatus
  ): Promise<void> {
    const userRecord = await this.userModel.findById(userId);
    if (!userRecord) {
      throw new UserNotFoundException(userId);
    }

    await userRecord.updateOne({
      status,
    });
  }

  public async updateUserPassword(
    userId: string,
    password: string
  ): Promise<void> {
    const userRecord = await this.userModel.findById(userId);
    if (!userRecord) {
      throw new UserNotFoundException(userId);
    }

    const passwordHash = await bcrypt.hash(password, 10);

    await userRecord.updateOne({
      passwordHash,
    });
  }

  public async changeUserPassword(
    userId: string,
    currentPassword: string,
    newPassword: string
  ): Promise<void> {
    const userRecord = await this.userModel.findById(userId);
    assertUserExists(userRecord, userId);

    const isCurrentPasswordCorrect = await bcrypt.compare(
      currentPassword,
      userRecord.passwordHash
    );

    if (!isCurrentPasswordCorrect) {
      throw new BadRequestException('Invalid current password');
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    userRecord.passwordHash = hashedNewPassword;
    await userRecord.save();
  }

  private async populateAndExecuteQuery<T>(find): Promise<T | undefined> {
    return (await find.exec()) ?? undefined;
  }

  private findEnabledUserByEmail(email: string): Promise<UserRecord | null> {
    return this.userModel.findOne({
      email: email.toLowerCase(),
      status: 'enabled',
    });
  }
}
