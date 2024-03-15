// Copyright 2024 applibrium.com

import { useEffect, useState } from 'react';
import { miningHardwareType } from '../../models/models';
import Root from '../../routes/root';
import {
  updateMiningHardware,
  addMiningHardware,
  getMiningHardware,
  deleteMiningHardware,
} from '../../service/mining-hardwares-service';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { MinerItem } from './components/hardware';

export default function MiningHardwarePage(): JSX.Element {
  const queryClient = useQueryClient();
  const queryMiningHardwares = useQuery({
    queryKey: ['miningHardwares'],
    queryFn: () => getMiningHardware(),
  });

  const addHardwareMutation = useMutation({
    mutationFn: (hardwareItem: miningHardwareType) =>
      addMiningHardware(hardwareItem),
    onSuccess: (data) => {
      // eslint-disable-next-line no-console
      console.log('Success', data);
    },
  });

  const editHardwareMutation = useMutation({
    mutationFn: (params: { id: string; hardwareItem: miningHardwareType }) =>
      updateMiningHardware(params.id, params.hardwareItem),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['miningHardwares'] });
    },
  });

  const deleteHardwareMutation = useMutation({
    mutationFn: (id: string) => deleteMiningHardware(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['miningHardwares'] });
    },
  });

  const [isEditing, setIsEditing] = useState(false);
  const [miners, setMiners] = useState<miningHardwareType[]>([]);
  const [newMiner, setNewMiner] = useState<miningHardwareType>({
    name: '',
    location: '',
    hashRate: '',
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>): void => {
    const { name, value } = e.target;
    setNewMiner((prevState) => ({
      ...prevState,
      [name]: value,
    }));
  };

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>): void => {
    e.preventDefault();

    const newMiningHardware: miningHardwareType = {
      name: newMiner.name,
      location: newMiner.location,
      hashRate: newMiner.hashRate,
    };
    if (isEditing) {
      if (newMiner.id) {
        editHardwareMutation.mutate({
          id: newMiner.id,
          hardwareItem: newMiningHardware,
        });
        setMiners((prevState) =>
          prevState.map((miner) =>
            miner.id === newMiner.id ? newMiner : miner
          )
        );
        setIsEditing(false);
      }
    } else {
      setMiners((prevState) => [...prevState, newMiner]);
      addHardwareMutation.mutate(newMiningHardware);
    }

    setNewMiner({ name: '', location: '', hashRate: '' });
  };

  useEffect(() => {
    if (queryMiningHardwaresData) {
      setMiners(queryMiningHardwaresData);
    }
  }, []);

  const handleEdit = (miningHardware: miningHardwareType): void => {
    setNewMiner({
      id: miningHardware.id,
      name: miningHardware.name,
      location: miningHardware.location,
      hashRate: miningHardware.hashRate,
    });

    setIsEditing(true);
  };

  const handleDelete = (id: string): void => {
    deleteHardwareMutation.mutate(id);
    setMiners((prevMiners) => prevMiners.filter((miner) => miner.id !== id));
  };

  const queryMiningHardwaresData = queryMiningHardwares.data;

  return (
    <div className="bg-gray-200 min-h-screen">
      {/* Header */}
      <Root />
      {/* Content */}
      <div className="p-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <div className="bg-white p-4 border border-gray-300 rounded-md">
              <h2 className="text-lg font-semibold mb-4">
                {isEditing ? 'Edit' : 'Add'} Mining Hardware
              </h2>
              <form onSubmit={handleSubmit}>
                <div className="mb-4">
                  <label htmlFor="name" className="block text-gray-700">
                    Name:
                  </label>
                  <input
                    type="text"
                    id="name"
                    name="name"
                    value={newMiner.name}
                    onChange={handleChange}
                    className="border border-gray-300 rounded-md px-3 py-2 w-full"
                    required
                  />
                </div>
                <div className="mb-4">
                  <label htmlFor="location" className="block text-gray-700">
                    Location:
                  </label>
                  <input
                    type="text"
                    id="location"
                    name="location"
                    value={newMiner.location}
                    onChange={handleChange}
                    className="border border-gray-300 rounded-md px-3 py-2 w-full"
                    required
                  />
                </div>
                <div className="mb-4">
                  <label htmlFor="hashRate" className="block text-gray-700">
                    Hash Rate:
                  </label>
                  <input
                    type="text"
                    id="hashRate"
                    name="hashRate"
                    value={newMiner.hashRate}
                    onChange={handleChange}
                    className="border border-gray-300 rounded-md px-3 py-2 w-full"
                    required
                  />
                </div>
                <button
                  type="submit"
                  className="bg-blue-500 text-white px-4 py-2 rounded-md"
                >
                  {isEditing ? 'Update' : 'Add'} Miner
                </button>
              </form>
            </div>
          </div>

          {queryMiningHardwares.isLoading ||
          addHardwareMutation.isPending ||
          editHardwareMutation.isPending ||
          deleteHardwareMutation.isPending ? (
            ' LOADING '
          ) : (
            <div className="bg-white border border-gray-300 rounded-md overflow-y-auto h-screen">
              <h2 className="text-lg font-semibold px-4 py-2 border-b border-gray-300">
                Mining Hardwares
              </h2>
              <div className="p-4">
                {miners &&
                  miners?.map((miner) => (
                    <MinerItem
                      key={miner.id}
                      miner={miner}
                      handleEdit={handleEdit}
                      handleDelete={handleDelete}
                    />
                  ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
