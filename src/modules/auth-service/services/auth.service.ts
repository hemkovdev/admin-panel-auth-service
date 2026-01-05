import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { LoginDto, SignUpDto } from '../dtos';
import type { Request } from 'express';
import { UserRepository } from 'src/modules/repositories';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { UserDocument } from '../schemas/auth.schema';
import { JwtService } from '@nestjs/jwt';
import { RefreshTokenRepository } from 'src/modules/repositories/refresh-token-repository';

@Injectable()
export class AuthService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly jwtService: JwtService,
    private readonly refreshTokenRepository: RefreshTokenRepository,
  ) {}

  async signup(dto: SignUpDto) {
    // console.info(`Signup started: email=${dto.email}`);
    const existingUser = await this.userRepository.findByEmail(dto?.email);
    if (existingUser) {
      //   console.warn(`Signup failed — email already exists: ${dto.email}`);
      throw new ForbiddenException('Email already registered');
    }

    const passwordHash = await bcrypt.hash(dto.password, 10);

    const user = await this.userRepository.createUser({
      id: uuidv4(),
      full_name: dto.full_name,
      email: dto.email,
      password: passwordHash,
      role: dto.role,
      status: 'active',
    });

    console.info(`Signup successful: userId=${user.id}`);
    return {
      user,
    };
  }
  async login(dto: LoginDto) {
    console.info(`Login attempt: email=${dto.email}`);
    const user = await this.userRepository.findByEmailWithPassword(dto.email);
    if (!user) {
      console.warn(`Login failed — user not found: ${dto.email}`);
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.status !== 'active') {
      console.warn(`Login blocked — user inactive: userId=${user.id}`);
      throw new ForbiddenException('User account is not active');
    }

    const accessToken = this.generateAccessToken(user);
    const refreshToken = await this.createRefreshToken(user);

    await this.userRepository.updateLastLogin(user.id);
    console.info(`Login successful: userId=${user.id}`);

    return {
      user,
      auth: {
        access_token: accessToken,
        expires_in: 3600,
      },
      refresh_token: refreshToken, // usually set as HttpOnly cookie
    };
  }
  async refreshToken(req: Request) {}
  async logout(req: Request) {}
  async me(req: Request) {}

  /**
   * ======================
   * HELPERS
   * ======================
   */

  private generateAccessToken(user: UserDocument): string {
    return this.jwtService.sign(
      {
        user_id: user.id,
        role: user.role,
        email: user.email,
      },
      {
        expiresIn: '1h',
      },
    );
  }

  private async createRefreshToken(user: UserDocument): Promise<string> {
    const rawToken = uuidv4();
    const tokenHash = await bcrypt.hash(rawToken, 10);

    await this.refreshTokenRepository.create({
      user_id: user.id,
      token_hash: tokenHash,
      expires_at: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
    }); // 7 days

    return rawToken;
  }
}
