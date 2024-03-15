// Copyright 2024 applibrium.com

import { miningHardwareType } from '../models/models';

export async function getMiningHardware(): Promise<miningHardwareType[]> {
  const response = await fetch('http://localhost:3000/mining-hardwares', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${localStorage.getItem('token')}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch mining hardware');
  }

  const data = await response.json();
  return data;
}

export async function addMiningHardware(
  miningHardware: miningHardwareType
): Promise<miningHardwareType> {
  const response = await fetch('http://localhost:3000/mining-hardwares', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${localStorage.getItem('token')}`,
    },
    body: JSON.stringify(miningHardware),
  });

  if (!response.ok) {
    throw new Error('Failed to add mining hardware');
  }

  const data = await response.json();
  return data;
}

export async function updateMiningHardware(
  id: string,
  miningHardware: miningHardwareType
): Promise<miningHardwareType> {
  const response = await fetch(`http://localhost:3000/mining-hardwares/${id}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${localStorage.getItem('token')}`,
    },
    body: JSON.stringify(miningHardware),
  });

  if (!response.ok) {
    throw new Error('Failed to add mining hardware');
  }

  const data = await response.json();
  return data;
}

export async function deleteMiningHardware(id: string): Promise<void> {
  const response = await fetch(`http://localhost:3000/mining-hardwares/${id}`, {
    method: 'DELETE',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${localStorage.getItem('token')}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to delete mining hardware');
  }
}
