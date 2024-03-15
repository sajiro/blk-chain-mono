// Copyright 2024 applibrium.com

import { ICreateMiningHardwareDto } from './create-mining-hardware.dto';

export type IUpdateMiningHardwareDto = Partial<
  Pick<ICreateMiningHardwareDto, 'location' | 'name' | 'hashRate'>
>;
