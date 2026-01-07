import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export enum UserRole {
  USER = 'USER',
  ADMIN = 'ADMIN',
}
export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  BLOCKED = 'blocked',
}

@Schema({ timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } })
export class User {
  @Prop({ required: true, unique: true, index: true })
  user_id: string;

  @Prop({ required: true })
  full_name: string;

  @Prop({
    required: true,
    unique: true,
    lowercase: true,
    index: true,
  })
  email: string;

  @Prop({ required: true, select: false })
  password: string;

  @Prop({
    type: String,
    enum: UserRole,
    default: UserRole?.USER,
  })
  role: UserRole;

  @Prop({
    type: String,
    enum: UserStatus,
    default: UserStatus.ACTIVE,
  })
  status: UserStatus;

  @Prop({ type: Boolean, default: false })
  is_email_verified: boolean;

  @Prop({ default: 0 })
  failed_login_attempts: number;

  @Prop({ default: null })
  last_login_at?: Date;

  @Prop({ default: null })
  password_changed_at?: Date;

  @Prop({ default: null })
  blocked_at?: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);

/**
 * Transformations
 * - Remove _id
 * - Remove password
 */
UserSchema.set('toJSON', {
  virtuals: true,
  versionKey: false,
  transform: function (doc, ret) {
    Reflect.deleteProperty(ret, '_id');
    Reflect.deleteProperty(ret, 'password');
    return ret;
  },
});

UserSchema.set('toObject', {
  virtuals: true,
  versionKey: false,
  transform: function (doc, ret) {
    Reflect.deleteProperty(ret, '_id');
    Reflect.deleteProperty(ret, 'password');
    return ret;
  },
});

/**
 * Indexes
 */
// UserSchema.index({ email: 1 });
UserSchema.index({ role: 1, status: 1 });

export type UserDocument = HydratedDocument<User>;
