import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

@Schema({ timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } })
export class RefreshToken {
  @Prop({ required: true })
  user_id: string;

  /**
   * Hashed refresh token (never store raw token)
   */
  @Prop({ required: true })
  token_hash: string;

  /**
   * Token expiry (used for validation + TTL cleanup)
   */
  @Prop({ required: true })
  expires_at: Date;

  /**
   * When user logs out or token is invalidated
   */
  @Prop({ default: null })
  revoked_at?: Date;
}

export const RefreshTokenSchema = SchemaFactory.createForClass(RefreshToken);

/**
 * Remove internal fields from responses
 */
RefreshTokenSchema.set('toJSON', {
  virtuals: true,
  versionKey: false,
  transform: function (doc, ret) {
    Reflect.deleteProperty(ret, '_id');
    Reflect.deleteProperty(ret, 'token_hash');
    return ret;
  },
});

RefreshTokenSchema.set('toObject', {
  virtuals: true,
  versionKey: false,
  transform: function (doc, ret) {
    Reflect.deleteProperty(ret, '_id');
    Reflect.deleteProperty(ret, 'token_hash');
    return ret;
  },
});

/**
 * Indexes
 */
RefreshTokenSchema.index({ user_id: 1 });
RefreshTokenSchema.index({ revoked_at: 1 });
RefreshTokenSchema.index({ expires_at: 1 });

/**
 * TTL index
 * Automatically deletes documents after expiry
 * (MongoDB background cleanup)
 */
RefreshTokenSchema.index(
  { expires_at: 1 },
  { expireAfterSeconds: 0 },
);

export type RefreshTokenDocument = HydratedDocument<RefreshToken>;

