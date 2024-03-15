// Copyright 2024 applibrium.com

import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';

import { getNewDate } from '@mine/shared/utils/datetime';
import { SKIP_AUTH_KEY } from './skip-auth.decorator';
import { IJwtDecodedPayload } from './models/jwt-payload';
import { extractTokenFromHeader } from './helpers/auth.helper';
import { AuthService } from './auth.service';
import { IConfiguration } from '../../models/configuration';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private authService: AuthService,
    private configService: ConfigService<IConfiguration, true>,
    private jwtService: JwtService,
    private reflector: Reflector
  ) {}

  public async canActivate(context: ExecutionContext): Promise<boolean> {
    const skipAuth = this.reflector.getAllAndOverride<boolean>(SKIP_AUTH_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (skipAuth) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const token = extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException();
    }

    let payload: IJwtDecodedPayload;

    try {
      const decoded = this.jwtService.decode(token) as IJwtDecodedPayload;

      if (getNewDate().getTime() > decoded.exp * 1000) {
        this.authService.deleteTokenFromWhiteList(token);

        throw new UnauthorizedException();
      }

      payload = await this.jwtService.verifyAsync<IJwtDecodedPayload>(token, {
        secret: this.configService.get('jwtAccessSecret', { infer: true }),
      });
    } catch {
      throw new UnauthorizedException();
    }

    const tokenDoc = await this.authService.findTokenInWhiteList(token);

    if (!tokenDoc) {
      throw new UnauthorizedException();
    }

    // 💡 We're assigning the payload to the request object here
    // so that we can access it in our route handlers
    request['user'] = payload;

    return true;
  }
}
