// Copyright 2024 applibrium.com

import { PencilSquareIcon, TrashIcon } from '@heroicons/react/24/outline';
import { miningHardwareType } from '../../../../src/models/models';

interface IMinerItemProps {
  miner: miningHardwareType;
  handleEdit: (miner: miningHardwareType) => void;
  handleDelete: (id: string) => void;
}

export const MinerItem: React.FC<IMinerItemProps> = ({
  miner,
  handleEdit,
  handleDelete,
}) => {
  return (
    <div
      key={miner?.id}
      className="mb-4 bg-gray-100 p-4 border border-gray-300 rounded-md flex justify-between items-center"
    >
      <div>
        <h3 className="text-lg font-semibold mb-2">{miner.name}</h3>
        <p>
          <strong>Location:</strong> {miner.location}
        </p>
        <p>
          <strong>Hash Rate:</strong> {miner.hashRate}
        </p>
      </div>
      <div>
        <button
          onClick={() => handleEdit(miner)}
          className="mr-2 text-blue-500"
        >
          <PencilSquareIcon className="w-6 h-6" />
        </button>
        <button
          onClick={() => {
            if (miner.id) {
              handleDelete(miner.id);
            }
          }}
          className="text-red-500"
        >
          <TrashIcon className="w-6 h-6" />
        </button>
      </div>
    </div>
  );
};
