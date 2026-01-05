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
        expires_in: process.env.JWT_ACCESS_EXPIRES_IN,
      },
      refresh_token: refreshToken, // usually set as HttpOnly cookie
    };
  }
  async refreshToken(refresh_token) {
    const token = refresh_token
    console.log("refresh_token", refresh_token)
    
    if(!token) {
      console.warn('Refresh token missing')
      throw new UnauthorizedException("Refresh token missing")
    }
    
    const storedToken = await this.refreshTokenRepository.findValidToken(token)
    console.log("refresh_token", refresh_token)

    if(!storedToken) {
      console.warn('Refresh token invalid or revoked')
      throw new ForbiddenException('Invalid refresh token')
    }

    const user = await this.userRepository.findById(storedToken.user_id)
    if(!user) {
      console.error(`Refresh failed - user not found: ${storedToken.user_id}`)
      throw new UnauthorizedException()
    }

    // ROTATE REFRESH TOKEN
    await this.refreshTokenRepository.revokeToken(refresh_token)

    const access_token = this.generateAccessToken(user)
    const new_refresh_token = this.createRefreshToken(user)

    console.info(`Access token refreshed: userId=${user.id}`)

    return {
      auth: {
        access_token,
        expires_in: process.env.JWT_ACCESS_EXPIRES_IN
      },
      refresh_token: new_refresh_token
    }
  }
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
        expiresIn: '30s',
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
