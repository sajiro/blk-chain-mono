// Copyright 2024 applibrium.com

import {
  Body,
  Req,
  Res,
  Controller,
  Post,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
  InternalServerErrorException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ApiBearerAuth,
  ApiBody,
  ApiInternalServerErrorResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { AccessTokenDto, SignInDto } from './dtos/auth.dto';
import { SkipAuth } from './skip-auth.decorator';
import {
  extractTokenFromHeader,
  refreshTokenCookieName,
} from './helpers/auth.helper';
import { IConfiguration } from '../../models/configuration';
import { assertIsTruthy } from '../../assertions/assert-is-truthy';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private configService: ConfigService<IConfiguration, true>
  ) {}

  @ApiBody({ type: SignInDto })
  @ApiOkResponse({
    description:
      'Successful login. Sends refresh token in http-only cookie "jwt_refresh_token" to the front-end.',
    type: AccessTokenDto,
  })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @SkipAuth()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  public async signIn(
    @Body() signInDto: SignInDto,
    @Res() res: Response
  ): Promise<Response<AccessTokenDto>> {
    const authTokens = await this.authService.signIn(
      signInDto.email,
      signInDto.password
    );

    if (!authTokens) {
      throw new UnauthorizedException();
    }

    const useHttps = this.configService.get('useHttps', { infer: true });
    const expiresInMilliseconds =
      parseInt(
        this.configService.get('jwtRefreshExpiresInMinutes', { infer: true })
      ) *
      60 *
      1000;

    res.cookie(refreshTokenCookieName, authTokens.refreshToken, {
      httpOnly: true,
      sameSite: 'none',
      secure: useHttps,
      maxAge: expiresInMilliseconds,
    });

    return res.json({ accessToken: authTokens.accessToken });
  }

  @ApiOkResponse({
    description: 'Successful refresh',
    type: AccessTokenDto,
  })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiInternalServerErrorResponse({ description: 'Internal error' })
  @SkipAuth()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  public async refresh(
    @Req() request: Request,
    @Res() res: Response
  ): Promise<Response<AccessTokenDto>> {
    const refreshToken = request.cookies[refreshTokenCookieName];

    if (!refreshToken) {
      throw new UnauthorizedException();
    }

    const accessToken = await this.authService.refresh(refreshToken);

    if (!accessToken) {
      throw new UnauthorizedException();
    }

    return res.json({ accessToken });
  }

  @ApiBearerAuth()
  @ApiNoContentResponse({ description: 'Successful logout' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiInternalServerErrorResponse({ description: 'Internal error' })
  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async signOut(@Req() request: Request): Promise<void> {
    const token = extractTokenFromHeader(request);
    assertIsTruthy(token, 'Authentication token not found');

    const deletedTokenDoc = await this.authService.signOut(token);

    if (!deletedTokenDoc) {
      throw new InternalServerErrorException('Unable to delete token');
    }
  }
}
