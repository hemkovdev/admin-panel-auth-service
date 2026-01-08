import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';

import { AuthService } from './services/auth.service';
import { AuthController } from './controllers/auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';

import { User, UserSchema } from './schemas/auth.schema';
import { RefreshToken, RefreshTokenSchema } from './schemas';

import { UserRepository } from '../repositories';
import { RefreshTokenRepository } from '../repositories/refresh-token-repository';

import { StringValue } from 'ms';

@Module({
  imports: [
    ConfigModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),

    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: RefreshToken.name, schema: RefreshTokenSchema },
    ]),

    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (cfg: ConfigService) => {
        const privateKey = cfg.getOrThrow<string>('JWT_ACCESS_PRIVATE_KEY');
        const publicKey = cfg.getOrThrow<string>('JWT_ACCESS_PUBLIC_KEY');

        console.log('JWT private key loaded:', !!privateKey);
        console.log('JWT public key loaded:', !!publicKey);

        return {
          privateKey: Buffer.from(privateKey, 'base64'),
          publicKey: Buffer.from(publicKey, 'base64'),
          signOptions: {
            algorithm: 'RS256',
            issuer: 'auth-service',
            audience: 'web-client',
            expiresIn: cfg.get('JWT_ACCESS_EXPIRES_IN') ?? '15m',
          },
        };
      },
    }),
  ],
  providers: [AuthService, JwtStrategy, UserRepository, RefreshTokenRepository],
  controllers: [AuthController],
})
export class AuthModule {}