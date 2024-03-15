// Copyright 2024 applibrium.com

import { Types } from 'mongoose';
import { MiningHardwareRecord } from '../schemas/mining-hardware.schema';

export const hardware1Mock: MiningHardwareRecord = {
  _id: new Types.ObjectId('flag-0000001'),
  name: 'avvvva',
  location: 'llca',
  hashRate: 'aaaa',
};

export const hardware2Mock: MiningHardwareRecord = {
  _id: new Types.ObjectId('flag-0000002'),
  name: 'aa',
  location: 'llca',
  hashRate: 'aaaa',
};
