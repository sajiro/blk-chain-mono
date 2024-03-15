// Copyright 2024 applibrium.com

import { DeepMocked, createMock } from '@golevelup/ts-jest';
import { MiningHardwaresService } from './mining-hardwares.service';
import { MiningHardwaresController } from './mining-hardwares.controller';
import { MiningHardwareRecord } from './schemas/mining-hardware.schema';
import { IMiningHardware } from '@mine/shared/models';
import {
  hardware1Mock,
  hardware2Mock,
} from './__mocks__/mining-hardwares.mock';
import {
  ICreateMiningHardwareDto,
  ICreatedIdDto,
  IUpdateMiningHardwareDto,
} from '@mine/shared/dtos';
import { AuthService } from '../auth/auth.service';
import { DeleteMiningHardwareParams } from './params/delete-mining-hardware.params';
import { UpdateMiningHardwareParams } from './params/update-mining-hardware.params';

describe('MiningHardwaresController', () => {
  let miningHardwaresServiceMock: DeepMocked<MiningHardwaresService>;
  let authServiceMock: DeepMocked<AuthService>;
  let controller: MiningHardwaresController;

  beforeEach(() => {
    jest.resetAllMocks();

    miningHardwaresServiceMock = createMock<MiningHardwaresService>();
    authServiceMock = createMock<AuthService>();
    controller = new MiningHardwaresController(
      miningHardwaresServiceMock,
      authServiceMock
    );
  });

  describe('getMiningHardwares', () => {
    it('returns mining hardwares', async () => {
      const miningHardwaresMock: MiningHardwareRecord[] = [
        hardware1Mock,
        hardware2Mock,
      ];
      miningHardwaresServiceMock.getMiningHardwares.mockResolvedValue(
        miningHardwaresMock
      );

      const miningHardwares = await controller.getMiningHardwares();

      const expectedMiningHardwares: IMiningHardware[] =
        miningHardwaresMock.map(({ _id, name, location, hashRate }) => ({
          id: _id.toString(),
          name,
          location,
          hashRate,
        }));
      expect(miningHardwares).toEqual(expectedMiningHardwares);
      expect(
        miningHardwaresServiceMock.getMiningHardwares
      ).toHaveBeenCalledOnce();
    });
  });

  describe('createMiningHardware', () => {
    it('creates mining hardware', async () => {
      const hardareIdMock = 'mining-hardware-id';
      miningHardwaresServiceMock.createMiningHardware.mockResolvedValue(
        hardareIdMock
      );

      const requestMock = {} as Request;
      const createDtoMock: ICreateMiningHardwareDto = {
        name: 'mining-hardware',
        location: 'location',
        hashRate: 'hash-rate',
      };

      const response = await controller.createMiningHardware(
        requestMock,
        createDtoMock
      );

      const expectedResponse: ICreatedIdDto = {
        id: hardareIdMock,
      };
      expect(response).toEqual(expectedResponse);

      expect(authServiceMock.ensureCurrentUserIsAdmin).toHaveBeenCalledOnceWith(
        requestMock
      );
      expect(
        miningHardwaresServiceMock.createMiningHardware
      ).toHaveBeenCalledOnceWith(
        createDtoMock.name,
        createDtoMock.location,
        createDtoMock.hashRate
      );
    });
  });

  describe('updateMiningHardware', () => {
    it('updates mining hardware', async () => {
      miningHardwaresServiceMock.updateMiningHardware.mockResolvedValue();

      const requestMock = {} as Request;
      const updateDtoMock: IUpdateMiningHardwareDto = {
        name: 'mining-hardware',
        location: 'location',
        hashRate: 'hash-rate',
      };

      const miningHardwareIdMock = 'mining-hardware-id';
      const paramsMock: UpdateMiningHardwareParams = {
        miningHardwareId: miningHardwareIdMock,
      };

      await controller.updateMiningHardware(
        requestMock,
        paramsMock,
        updateDtoMock
      );

      expect(authServiceMock.ensureCurrentUserIsAdmin).toHaveBeenCalledOnceWith(
        requestMock,
        authServiceMock
      );
      expect(
        miningHardwaresServiceMock.updateMiningHardware
      ).toHaveBeenCalledOnceWith(
        miningHardwareIdMock,
        updateDtoMock.name,
        updateDtoMock.location,
        updateDtoMock.hashRate
      );
    });
  });

  describe('deleteMiningHardware', () => {
    it('deletes mining hardware', async () => {
      miningHardwaresServiceMock.deleteMiningHardware.mockResolvedValue();

      const requestMock = {} as Request;
      const hardareIdMock = 'mining-hardware-id';
      const paramsMock: DeleteMiningHardwareParams = {
        miningHardwareId: hardareIdMock,
      };

      await controller.deleteMiningHardware(requestMock, paramsMock);

      expect(authServiceMock.ensureCurrentUserIsAdmin).toHaveBeenCalledOnceWith(
        requestMock
      );
      expect(
        miningHardwaresServiceMock.deleteMiningHardware
      ).toHaveBeenCalledOnceWith(hardareIdMock);
    });
  });
});
