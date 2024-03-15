// Copyright 2024 applibrium.com

import { useQuery } from '@tanstack/react-query';
import { BlockchainService, CoinGeckoService } from '../../../service/service';
import { getMiningHardware } from '../../..//service/mining-hardwares-service';
import Root from '../../../routes/root';
import { miningHardwareType } from '../../../../src/models/models';
import {
  calculateTotalMiningRevenue,
  extractHashRate,
} from '../../../../src/service/helper';

export function DashboardScreen(): JSX.Element {
  const query = useQuery({
    queryKey: ['coinPrice', 'bitcoin', 'usd'],
    queryFn: () => CoinGeckoService.getPrice('bitcoin', 'usd'),
  });
  const queryBitcoin = useQuery({
    queryKey: ['difficulty'],
    queryFn: () => BlockchainService.getDifficulty(),
  });

  const queryMiningHardwares = useQuery({
    queryKey: ['miningHardwares'],
    queryFn: () => getMiningHardware(),
  });

  const bitcoinPrice = query.data;
  const miningDifficulty = queryBitcoin.data;
  const mininghardwares = queryMiningHardwares.data;

  const totalHashRate: number =
    mininghardwares?.reduce(
      (accumulator: number, currentValue: miningHardwareType) => {
        // Extract numeric hash rate from the string and add to accumulator
        return accumulator + extractHashRate(currentValue.hashRate);
      },
      0
    ) ?? 0;

  const totalMiningRevenue = calculateTotalMiningRevenue(
    mininghardwares ?? [],
    //TODO remove any later
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    bitcoinPrice as any
  );

  return (
    <div className="bg-gray-200 min-h-screen">
      {/* Header */}
      <Root />

      {/* Content */}
      <div className="p-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4">
          <div className="bg-white p-4 rounded-md shadow-md">
            <h3 className="text-lg font-semibold mb-2">Total Hash Rate</h3>
            <p className="text-gray-700">{totalHashRate}</p>
          </div>

          <div className="bg-white p-4 rounded-md shadow-md">
            <h3 className="text-lg font-semibold mb-2">Active Miners</h3>
            <p className="text-gray-700">{mininghardwares?.length}</p>
          </div>

          <div className="bg-white p-4 rounded-md shadow-md">
            <h3 className="text-lg font-semibold mb-2">Bitcoin Price</h3>
            <p className="text-gray-700">
              {query.isLoading ? 'Loading...' : `$${bitcoinPrice}`}
            </p>
          </div>

          <div className="bg-white p-4 rounded-md shadow-md">
            <h3 className="text-lg font-semibold mb-2">Mining Revenue</h3>
            <p className="text-gray-700">{totalMiningRevenue}</p>
          </div>

          <div className="bg-white p-4 rounded-md shadow-md col-span-2">
            <h3 className="text-lg font-semibold mb-2">Mining Difficulty</h3>
            <p className="text-gray-700">
              {queryBitcoin.isLoading ? 'Loading...' : miningDifficulty}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
