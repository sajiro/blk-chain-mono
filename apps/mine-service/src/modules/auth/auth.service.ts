// Copyright 2024 applibrium.com

import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { AuthTokens } from './models/auth-tokens';
import { IJwtDecodedPayload, IJwtSignPayload } from './models/jwt-payload';
import { AccessTokenRecord } from './schemas/access-token.schema';
import { IConfiguration } from '../../models/configuration';
import { UserRecord } from '../users/schemas/user.schema';
import { getCurrentUserId } from '../../utils/api.helper';
import { assertUserExists } from '../../assertions/assert-user-exists';
import { assertUserRoleIsAdmin } from '../../assertions/assert-user-role-is-admin';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService<IConfiguration, true>,
    @InjectModel(AccessTokenRecord.name)
    private accessTokenModel: Model<AccessTokenRecord>,
    @InjectModel(UserRecord.name)
    private userModel: Model<UserRecord>
  ) {}

  public async signIn(
    email: string,
    password: string
  ): Promise<AuthTokens | undefined> {
    const user = await this.userModel.findOne({
      email: email.toLowerCase(),
      status: 'enabled',
    });
    if (!user) {
      return undefined;
    }

    try {
      if (await bcrypt.compare(password, user.passwordHash)) {
        const payload: IJwtSignPayload = {
          username: user.email,
          sub: user._id.toString(),
        };
        const accessToken = await this.jwtService.signAsync(payload);

        this.saveOneToken(accessToken, email);

        const expiresInSeconds =
          parseInt(
            this.configService.get('jwtRefreshExpiresInMinutes', {
              infer: true,
            })
          ) * 60;
        const refreshToken = await this.jwtService.signAsync(payload, {
          secret: this.configService.get('jwtRefreshSecret', { infer: true }),
          expiresIn: expiresInSeconds,
        });

        const tokens: AuthTokens = {
          accessToken,
          refreshToken,
        };
        return tokens;
      }

      return undefined;
    } catch {
      return undefined;
    }
  }

  public async refresh(refreshToken: string): Promise<string | undefined> {
    let accessToken: string;

    try {
      const refreshPayload =
        await this.jwtService.verifyAsync<IJwtDecodedPayload>(refreshToken, {
          secret: this.configService.get('jwtRefreshSecret', { infer: true }),
        });

      const accessPayload: IJwtSignPayload = {
        username: refreshPayload.username,
        sub: refreshPayload.sub,
      };
      const expiresInSeconds =
        parseInt(
          this.configService.get('jwtAccessExpiresInMinutes', { infer: true })
        ) * 60;

      accessToken = await this.jwtService.signAsync(accessPayload, {
        secret: this.configService.get('jwtAccessSecret', { infer: true }),
        expiresIn: expiresInSeconds,
      });
      this.saveOneToken(accessToken, accessPayload.username);
    } catch (error) {
      return undefined;
    }

    return accessToken;
  }

  public async signOut(token: string): Promise<AccessTokenRecord | undefined> {
    const tokenDoc = await this.findTokenInWhiteList(token);

    if (!tokenDoc) {
      return undefined;
    }

    try {
      await this.deleteTokenFromWhiteList(token);
    } catch {
      return undefined;
    }

    return tokenDoc;
  }

  public async findTokenInWhiteList(
    token: string
  ): Promise<AccessTokenRecord | undefined> {
    try {
      const tokenDoc = await this.accessTokenModel.findOne({ token }).exec();

      return tokenDoc ?? undefined;
    } catch {
      return undefined;
    }
  }

  public async deleteTokenFromWhiteList(token: string): Promise<void> {
    await this.accessTokenModel.deleteMany({ token }).exec();
  }

  public async ensureCurrentUserIsAdmin(request: Request): Promise<UserRecord> {
    const currentUserId = getCurrentUserId(request);
    const currentUserRecord = await this.userModel.findById(currentUserId);

    assertUserExists(currentUserRecord, currentUserId);
    assertUserRoleIsAdmin(currentUserRecord.role);

    return currentUserRecord;
  }

  private async saveOneToken(
    accessToken: string,
    email: string
  ): Promise<void> {
    const tokenDoc: AccessTokenRecord = {
      token: accessToken,
      userEmail: email,
    };

    // store at most one access token for each user email
    await this.accessTokenModel.deleteMany({ userEmail: email }).exec();
    await this.accessTokenModel.create(tokenDoc);
  }
}
