import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { RefreshToken, RefreshTokenDocument } from '../auth-service/schemas';

@Injectable()
export class RefreshTokenRepository {
  constructor(
    @InjectModel(RefreshToken.name)
    private readonly refreshTokenModel: Model<RefreshTokenDocument>,
  ) {}

  /**
   * Create refresh token entry
   */
  async create(data: {
    user_id: string;
    token_hash: string;
    expires_at: Date;
    device_info?: string;
  }): Promise<RefreshTokenDocument> {
    console.info(`Creating refresh token for userId=${data.user_id}`);

    const token = new this.refreshTokenModel({
      user_id: data.user_id,
      token_hash: data.token_hash,
      expires_at: data.expires_at,
      device_info: data.device_info,
    });

    return token.save();
  }

  /**
   * Find valid refresh token by raw token
   * Used during refresh-token flow
   */
  async findValidToken(rawToken: string): Promise<RefreshTokenDocument | null> {
    const tokens = await this.refreshTokenModel
      .find({
        revoked_at: null,
        expires_at: { $gt: new Date() },
      })
      .exec();

    for (const token of tokens) {
      console.log('rawToken:', rawToken);
      console.log('token_hash:', token);

      const match = await bcrypt.compare(rawToken, token.token_hash);
      if (match) {
        return token;
      }
    }

    return null;
  }

  /**
   * Revoke refresh token (logout)
   */
  async revokeToken(rawToken: string): Promise<void> {
    const tokens = await this.refreshTokenModel
      .find({ revoked_at: null })
      .exec();

    for (const token of tokens) {
      const match = await bcrypt.compare(rawToken, token.token_hash);
      if (match) {
        token.revoked_at = new Date();
        await token.save();
        console.info(`Refresh token revoked: tokenId=${token.id}`);
        return;
      }
    }
  }

  /**
   * Revoke all refresh tokens for a user (logout all devices)
   */
  async revokeAllForUser(userId: string): Promise<void> {
    await this.refreshTokenModel.updateMany(
      { user_id: userId, revoked_at: null },
      { $set: { revoked_at: new Date() } },
    );

    console.info(`All refresh tokens revoked for userId=${userId}`);
  }
}
