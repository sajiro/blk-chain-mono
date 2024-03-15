// Copyright 2024 applibrium.com

import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { MiningHardwareRecord } from './schemas/mining-hardware.schema';
import { Model } from 'mongoose';

@Injectable()
export class MiningHardwaresService {
  constructor(
    @InjectModel(MiningHardwareRecord.name)
    private miningHardwareModel: Model<MiningHardwareRecord>
  ) {}

  public async getMiningHardwares(): Promise<MiningHardwareRecord[]> {
    const miningHardwares = await this.miningHardwareModel.find().exec();

    return miningHardwares;
  }

  public async createMiningHardware(
    name: string,
    location: string,
    hashRate: string
  ): Promise<string> {
    const trimmedKey = name.trim();

    const existingMiningHardware = await this.findMiningHardwareByName(
      trimmedKey
    );
    if (existingMiningHardware) {
      throw new ConflictException(`Key '${trimmedKey}' already exists`);
    }

    const miningHardwareModel = new this.miningHardwareModel({
      name: trimmedKey,
      location,
      hashRate,
    });

    const miningHardwareId = (await miningHardwareModel.save())?.id;
    if (!miningHardwareId) {
      throw new InternalServerErrorException('Failed to save mining hardware');
    }

    return miningHardwareId;
  }

  public async updateMiningHardware(
    miningHardwareId: string,
    name: string,
    location: string,
    hashRate: string
  ): Promise<void> {
    const miningHardware = await this.miningHardwareModel.findById(
      miningHardwareId
    );

    if (!miningHardware) {
      throw new NotFoundException(
        `Mining  hardware with id '${miningHardwareId}' not found`
      );
    }
    await miningHardware.updateOne({ name, location, hashRate });
  }

  public async deleteMiningHardware(miningHardwareId: string): Promise<void> {
    const miningHardware = await this.miningHardwareModel.findById(
      miningHardwareId
    );

    if (!miningHardware) {
      throw new NotFoundException(
        `Mining  hardware with id '${miningHardwareId}' not found`
      );
    }

    await miningHardware.deleteOne();
  }

  private findMiningHardwareByName(
    trimmedKey: string
  ): Promise<MiningHardwareRecord | null> {
    const miningHardwareKeyRegex = '^' + trimmedKey + '$';

    return this.miningHardwareModel.findOne({
      key: { $regex: miningHardwareKeyRegex, $options: 'i' },
    });
  }
}
