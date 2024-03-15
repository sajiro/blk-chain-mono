// Copyright 2024 applibrium.com

import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';
import { ApiProperty } from '@nestjs/swagger';
import { HydratedDocument } from 'mongoose';

export type AccessTokenDocument = HydratedDocument<AccessTokenRecord>;

@Schema({ collection: 'accessTokens' })
export class AccessTokenRecord {
  @ApiProperty()
  @Prop({ required: true })
  public token: string;

  @ApiProperty()
  @Prop({ required: true })
  public userEmail: string;
}

const AccessTokenSchema = SchemaFactory.createForClass(AccessTokenRecord);

export { AccessTokenSchema };
