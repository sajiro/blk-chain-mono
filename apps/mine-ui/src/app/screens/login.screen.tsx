// Copyright 2024 applibrium.com

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import { SignIn } from '../../service/auth-service';

const LoginPage: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const mutation = useMutation({
    mutationFn: ({ email, password }: { email: string; password: string }) =>
      SignIn(email, password),
    onSuccess: () => {
      navigate('/dashboard');
    },
  });

  const handleLogin = (): void => {
    mutation.mutate({ email: username, password });
  };

  return (
    <div className="flex h-screen bg-gray-200">
      <div className="m-auto p-8 max-w-md bg-white shadow-md rounded-md">
        <h2 className="text-2xl font-semibold mb-4">Login</h2>
        <div className="mb-4">
          <label
            htmlFor="username"
            className="block text-sm font-medium text-gray-600"
          >
            Username
          </label>
          <input
            type="text"
            id="username"
            name="username"
            value={username}
            // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
            onChange={(e) => setUsername(e.target.value)}
            className="mt-1 p-2 w-full border rounded-md"
          />
        </div>
        <div className="mb-4">
          <label
            htmlFor="password"
            className="block text-sm font-medium text-gray-600"
          >
            Password
          </label>
          <input
            type="password"
            id="password"
            name="password"
            value={password}
            // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 p-2 w-full border rounded-md"
          />
        </div>
        <button
          onClick={handleLogin}
          className="w-full bg-blue-500 text-white p-2 rounded-md hover:bg-blue-600"
        >
          Login
        </button>
      </div>
    </div>
  );
};

export default LoginPage;
