import { Injectable } from '@nestjs/common';
import { User, UserDocument } from '../auth-service/schemas/auth.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';

@Injectable()
export class UserRepository {
  constructor(
    @InjectModel(User.name)
    private readonly userModel: Model<UserDocument>,
  ) {}

  /**
   * Create new user
   */

  async createUser(data: any): Promise<UserDocument> {
    const user = this.userModel.create(data);
    return user;
  }

  /**
   * Find user by email (without password)
   */
  async findByEmail(email: string): Promise<UserDocument | null> {
    return this.userModel.findOne({ email }).exec();
  }

  /**
   * Find user by email (with password)
   * Used ONLY for login
   */
  async findByEmailWithPassword(email: string): Promise<UserDocument | null> {
    return this.userModel.findOne({ email }).select('+password').exec();
  }

  /**
   * Find user by ID
   */
  async findById(userId: string): Promise<UserDocument | null> {
    return this.userModel.findOne({ user_id: userId }).exec();
  }

  /**
   * Update last login timestamp
   */
  async updateLastLogin(userId: string): Promise<void> {
    await this.userModel.updateOne(
      { id: userId },
      { $set: { last_login_at: new Date() } },
    );
  }

  /**
   * Soft block user
   */
  async blockUser(userId: string): Promise<void> {
    await this.userModel.updateOne(
      { id: userId },
      {
        $set: {
          status: 'blocked',
          blocked_at: new Date(),
        },
      },
    );
  }
}
