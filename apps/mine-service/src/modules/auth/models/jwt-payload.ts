// Copyright 2024 applibrium.com

export interface IJwtSignPayload {
  username: string;
  sub: string;
}

export interface IJwtDecodedPayload extends IJwtSignPayload {
  iat: number;
  exp: number;
}
