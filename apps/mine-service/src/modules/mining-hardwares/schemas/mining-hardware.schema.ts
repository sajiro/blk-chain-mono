// Copyright 2024 applibrium.com

/* import { Environment } from '@mine/shared/models'; */
import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';

export type MiningHardwareDocument = HydratedDocument<MiningHardwareRecord>;

@Schema({ collection: 'miningHardwares' })
export class MiningHardwareRecord {
  public _id: Types.ObjectId;

  @Prop({ required: true })
  public name: string;

  @Prop({ required: true })
  public location: string;

  @Prop({ required: true })
  public hashRate: string;
}

const MiningHardwareSchema = SchemaFactory.createForClass(MiningHardwareRecord);

export { MiningHardwareSchema };
