// Copyright 2024 applibrium.com

import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Req,
} from '@nestjs/common';
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
import { MiningHardware } from './models/mining-hardware';
import { MiningHardwaresService } from './mining-hardwares.service';
import { SkipAuth } from '../auth/skip-auth.decorator';
import { ICreatedIdDto } from '@mine/shared/dtos';
import { CreateMiningHardwareDto } from './dtos/create-mining-hardware.dto';
import { UpdateMiningHardwareDto } from './dtos/update-mining-hardware.dto';
import { UpdateMiningHardwareParams } from './params/update-mining-hardware.params';
import { AuthService } from '../auth/auth.service';
import { DeleteMiningHardwareParams } from './params/delete-mining-hardware.params';

@ApiTags('mining  hardwares')
@Controller('mining-hardwares')
export class MiningHardwaresController {
  constructor(
    private miningHardwaresService: MiningHardwaresService,
    private authService: AuthService
  ) {}

  @ApiOkResponse({
    description: 'Success',
    type: MiningHardware,
    isArray: true,
  })
  @ApiInternalServerErrorResponse({ description: 'Internal error' })
  @SkipAuth()
  @Get()
  public async getMiningHardwares(): Promise<MiningHardware[]> {
    const miningHardwares =
      await this.miningHardwaresService.getMiningHardwares();

    return miningHardwares.map(({ _id, name, location, hashRate }) => ({
      id: _id.toString(),

      name,
      location,
      hashRate,
    }));
  }

  @ApiCreatedResponse()
  @ApiBearerAuth()
  @ApiBadRequestResponse({ description: 'Bad request' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiForbiddenResponse({ description: "User's role is not 'admin'" })
  @ApiConflictResponse({ description: 'Key already exists for environment' })
  @ApiInternalServerErrorResponse({ description: 'Internal error' })
  @Post()
  public async createMiningHardware(
    @Req() request,
    @Body()
    { name, location, hashRate }: CreateMiningHardwareDto
  ): Promise<ICreatedIdDto> {
    await this.authService.ensureCurrentUserIsAdmin(request);

    const id = await this.miningHardwaresService.createMiningHardware(
      name,
      location,
      hashRate
    );
    return { id };
  }

  @ApiBearerAuth()
  @ApiNoContentResponse({ description: 'No content' })
  @ApiBadRequestResponse({ description: 'Bad request' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiForbiddenResponse({ description: "User's role is not 'admin'" })
  @ApiNotFoundResponse({ description: 'Mining  hardware id not found' })
  @ApiInternalServerErrorResponse({ description: 'Internal error' })
  @ApiParam({ required: true, name: 'miningHardwareId' })
  @HttpCode(HttpStatus.NO_CONTENT)
  @Patch(':miningHardwareId')
  public async updateMiningHardware(
    @Req() request,
    @Param() { miningHardwareId }: UpdateMiningHardwareParams,
    @Body()
    { name, location, hashRate }: UpdateMiningHardwareDto
  ): Promise<void> {
    if (!miningHardwareId || !name || !location || !hashRate) {
      throw new BadRequestException('All parameters must be provided');
    }

    await this.authService.ensureCurrentUserIsAdmin(request);

    await this.miningHardwaresService.updateMiningHardware(
      miningHardwareId,
      name,
      location,
      hashRate
    );
  }

  @ApiBearerAuth()
  @ApiNoContentResponse({ description: 'No content' })
  @ApiBadRequestResponse({ description: 'Bad request' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiForbiddenResponse({ description: "User's role is not 'admin'" })
  @ApiNotFoundResponse({ description: 'Mining  hardware id not found' })
  @ApiInternalServerErrorResponse({ description: 'Internal error' })
  @ApiParam({ required: true, name: 'miningHardwareId' })
  @HttpCode(HttpStatus.NO_CONTENT)
  @Delete(':miningHardwareId')
  public async deleteMiningHardware(
    @Req() request,
    @Param() { miningHardwareId }: DeleteMiningHardwareParams
  ): Promise<void> {
    await this.authService.ensureCurrentUserIsAdmin(request);

    await this.miningHardwaresService.deleteMiningHardware(miningHardwareId);
  }
}
