// Copyright 2024 applibrium.com

import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';
import * as bcrypt from 'bcrypt';

import { UserRole, UserStatus } from '@mine/shared/models';

export type UserDocument = HydratedDocument<UserRecord>;

@Schema({ collection: 'users' })
export class UserRecord {
  public _id: Types.ObjectId;

  @Prop({ required: true })
  public firstName: string;

  @Prop({ required: true })
  public lastName: string;

  @Prop({ required: true })
  public email: string;

  @Prop({ required: true, default: 'member', type: String })
  public role: UserRole;

  @Prop({ required: true, default: 'enabled', type: String })
  public status: UserStatus;

  @Prop()
  public passwordHash: string;
}

const UserSchema = SchemaFactory.createForClass(UserRecord);

UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.passwordHash = await bcrypt.hash(this.passwordHash, 10);
  next();
});

export { UserSchema };
