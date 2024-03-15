// Copyright 2024 applibrium.com

type BitCoinPriceType = {
  ids: string;
  vs_currencies: string;
};

/* export const CoinGeckoService = async (
  ids: string,
  vs_currencies: string
): Promise<BitCoinPriceType> => {
  const response = await fetch(
    `https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=${vs_currencies}`
  );

  if (!response.ok) {
    throw new Error('Network response was not ok');
  }

  const data = await response.json();
  return data[ids][vs_currencies];
};
 */

export class CoinGeckoService {
  public static async getPrice(
    ids: string,
    vs_currencies: string
  ): Promise<BitCoinPriceType> {
    const response = await fetch(
      `https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=${vs_currencies}`
    );

    if (!response.ok) {
      throw new Error('Network response was not ok');
    }

    const data = await response.json();
    return data[ids][vs_currencies];
  }
}

export class BlockchainService {
  public static async getDifficulty(): Promise<string> {
    const response = await fetch(`https://blockchain.info/q/getdifficulty`);

    if (!response.ok) {
      throw new Error('Network response was not ok');
    }

    const data = await response.json();

    return data;
  }
}
