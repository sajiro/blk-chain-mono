// Copyright 2024 applibrium.com

import { getModelToken } from '@nestjs/mongoose';
import { Test } from '@nestjs/testing';
import { MiningHardwaresService } from './mining-hardwares.service';
import { MiningHardwareRecord } from './schemas/mining-hardware.schema';
import { hardware1Mock } from './__mocks__/mining-hardwares.mock';
import {
  ConflictException,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { Types } from 'mongoose';

describe('MiningHardwaresService', () => {
  let miningHardwaresService: MiningHardwaresService;

  type ModelConstructorArgs = Omit<MiningHardwareRecord, '_id'>;

  let findSpy: jest.SpyInstance;
  let findExecMock: jest.Mock;

  class MiningHardwareModelMock {
    public static data: ModelConstructorArgs;

    constructor(data: ModelConstructorArgs) {
      MiningHardwareModelMock.data = data;
    }

    public static find = jest.fn();
    public static findOne = jest.fn();
    public static findById = jest.fn();

    public save(): Promise<{ id: string } | undefined> {
      return Promise.resolve(undefined);
    }
  }

  beforeEach(async () => {
    jest.resetAllMocks();

    const moduleRef = await Test.createTestingModule({
      providers: [
        MiningHardwaresService,
        {
          provide: getModelToken(MiningHardwareRecord.name),
          useValue: MiningHardwareModelMock,
        },
      ],
    }).compile();

    miningHardwaresService = moduleRef.get<MiningHardwaresService>(
      MiningHardwaresService
    );

    findExecMock = jest.fn();
    findSpy = jest
      .spyOn(MiningHardwareModelMock, 'find')
      .mockReturnValue({ exec: findExecMock });
  });

  describe('getMiningHardwares', () => {
    it('returns all mining hardwares', async () => {
      const miningHardwaresMock: MiningHardwareRecord[] = [
        {
          _id: new Types.ObjectId('65f2770d71902b8bec5c0303'),
          name: 'Hardware 1',
          location: 'Location 1',
          hashRate: 'HashRate 1',
        },
        {
          _id: new Types.ObjectId('65f2770d71902b8bec5c0302'),
          name: 'Hardware 2',
          location: 'Location 2',
          hashRate: 'HashRate 2',
        },
      ];
      findExecMock.mockResolvedValue(miningHardwaresMock);

      const miningHardwares = await miningHardwaresService.getMiningHardwares();

      expect(miningHardwares).toEqual(miningHardwaresMock);
      expect(findSpy).toHaveBeenCalled();
    });
  });

  describe('createMiningHardware', () => {
    it('throws Conflict if mining hardware with name already exists', async () => {
      const findOneSpy = jest
        .spyOn(MiningHardwareModelMock, 'findOne')
        .mockResolvedValue(MiningHardwareModelMock);

      const nameMock = '  mining-hardware-name  ';
      const locationMock = 'location';
      const hashRateMock = 'hash-rate';

      try {
        await miningHardwaresService.createMiningHardware(
          nameMock,
          locationMock,
          hashRateMock
        );
        expect.assertions(1);
      } catch (error) {
        expect(error).toEqual(
          new ConflictException(`Key '${nameMock.trim()}' already exists`)
        );
      }

      const miningHardwareIdKeyRegex = '^' + nameMock.trim() + '$';
      expect(findOneSpy).toHaveBeenCalledWith({
        key: { $regex: miningHardwareIdKeyRegex, $options: 'i' },
      });
    });

    it('creates mining hardware', async () => {
      const miningHardwareIdMock = 'mining-hardware-id';

      const saveSpy = jest
        .spyOn(MiningHardwareModelMock.prototype, 'save')
        .mockResolvedValue({ id: miningHardwareIdMock });

      jest.spyOn(MiningHardwareModelMock, 'findOne').mockResolvedValue(null);

      const nameMock = '  mining-hardware-name  ';
      const locationMock = 'location';
      const hashRateMock = 'hash-rate';

      const miningHardwareId =
        await miningHardwaresService.createMiningHardware(
          nameMock,
          locationMock,
          hashRateMock
        );

      expect(miningHardwareId).toEqual(miningHardwareIdMock);
      expect(saveSpy).toHaveBeenCalledOnceWith();

      const expectedConstructorArgs = {
        name: nameMock.trim(),
        location: locationMock,
        hashRate: hashRateMock,
      };

      expect(MiningHardwareModelMock.data).toEqual(expectedConstructorArgs);
    });

    it('throws internal error if create fails', async () => {
      jest
        .spyOn(MiningHardwareModelMock.prototype, 'save')
        .mockResolvedValue(undefined);
      jest.spyOn(MiningHardwareModelMock, 'findOne').mockResolvedValue(null);

      const nameMock = '  mining-hardware-name  ';
      const locationMock = 'location';
      const hashRateMock = 'hash-rate';

      try {
        await miningHardwaresService.createMiningHardware(
          nameMock,
          locationMock,
          hashRateMock
        );
        expect.assertions(1);
      } catch (error) {
        expect(error).toEqual(
          new InternalServerErrorException('Failed to save mining hardware')
        );
      }
    });
  });

  describe('updateMiningHardware', () => {
    it('throws Not Found if mining hardware with id does not exist', async () => {
      const findByIdSpy = jest
        .spyOn(MiningHardwareModelMock, 'findById')
        .mockResolvedValue(null);

      const miningHardwareIdMock = 'mining-hardware-id';

      try {
        await miningHardwaresService.updateMiningHardware(
          miningHardwareIdMock,
          'name',
          'location',
          'hash-rate'
        );
        expect.assertions(1);
      } catch (error) {
        expect(error).toEqual(
          new NotFoundException(
            `Mining  hardware with id '${miningHardwareIdMock}' not found`
          )
        );
      }

      expect(findByIdSpy).toHaveBeenCalledOnceWith(miningHardwareIdMock);
    });

    it.each([['name1'], ['name2']])(
      'updates mining hardware (name: %p)',
      async (nameMock: string) => {
        const updateOneMock = jest.fn();
        const miningHardwareMock = {
          ...hardware1Mock,
          updateOne: updateOneMock,
        };

        jest
          .spyOn(MiningHardwareModelMock, 'findById')
          .mockResolvedValue(miningHardwareMock);

        await miningHardwaresService.updateMiningHardware(
          'mining-hardware-id',
          nameMock,
          'location',
          'hash-rate'
        );

        if (nameMock !== undefined) {
          expect(updateOneMock).toHaveBeenCalledOnceWith({
            name: nameMock,
            location: 'location',
            hashRate: 'hash-rate',
          });
        } else {
          expect(updateOneMock).not.toHaveBeenCalled();
        }
      }
    );
  });

  it('deletes mining hardware', async () => {
    const deleteOneMock = jest.fn();
    const miningHardwareMock = {
      ...hardware1Mock,
      deleteOne: deleteOneMock,
    };

    jest
      .spyOn(MiningHardwareModelMock, 'findById')
      .mockResolvedValue(miningHardwareMock);

    await miningHardwaresService.deleteMiningHardware('mining-hardware-id');

    expect(deleteOneMock).toHaveBeenCalledOnceWith();
    expect(MiningHardwareModelMock.findById).toHaveBeenCalledWith(
      'mining-hardware-id'
    );
  });
});
