// Copyright 2024 applibrium.com

import { miningHardwareType } from '../models/models';

export const extractHashRate = (hashRateString: string): number => {
  // Extract the numeric part of the hash rate string

  const numericPart = parseFloat(hashRateString);
  /*     // eslint-disable-next-line no-console
  console.log('numericPart', numericPart); */
  if (isNaN(numericPart)) {
    // eslint-disable-next-line no-console
    console.warn('Received NaN for hash rate string:', hashRateString);
  }

  // Return the numeric part
  return numericPart;
};

export const calculateTotalMiningRevenue = (
  miners: miningHardwareType[],
  bitcoinPrice: number
): number => {
  let totalRevenue = 0;
  for (const miner of miners) {
    const hashRateStr = miner.hashRate;
    // Extract hash rate value from string and convert to TH/s
    const hashRate = parseFloat(hashRateStr.split(' ')[0]);
    // Calculate revenue for this miner (assuming revenue is proportional to hash rate)
    const minerRevenue = hashRate * bitcoinPrice;
    // Add miner revenue to total revenue
    totalRevenue += minerRevenue;
  }
  return totalRevenue;
};

export const calculateTotalHashes = (
  hashRate: string,
  durationInDays: number
): number => {
  const hashRateInTHS = extractHashRate(hashRate); // Convert hash rate to TH/s
  const secondsInADay = 24 * 60 * 60;
  const totalSecondsInPeriod = durationInDays * secondsInADay;
  const totalHashes = hashRateInTHS * totalSecondsInPeriod;
  return totalHashes;
};
