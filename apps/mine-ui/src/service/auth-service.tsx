// Copyright 2024 applibrium.com

export function SaveData(items: { key: string; data: string }[]): void {
  items.forEach((item) => localStorage.setItem(item.key, item.data));
}

export function IsLoggedIn(key: string): boolean {
  const item = localStorage.getItem(key);
  return !!item;
}

export function removeData(keys: string[]): void {
  keys.forEach((key) => localStorage.removeItem(key));
}

export function GetCurrenData(key: string): string | null {
  return localStorage.getItem(key);
}

export async function SignIn(email: string, password: string): Promise<string> {
  const response = await fetch('http://localhost:3000/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    throw new Error('Login failed');
  }

  const data = await response.json();

  SaveData([
    { key: 'token', data: data.accessToken },
    { key: 'user', data: email },
  ]);

  return data;
}
