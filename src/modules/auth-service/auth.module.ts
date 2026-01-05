import { Module } from '@nestjs/common';
import { AuthService } from './services/auth.service';
import { AuthController } from './controllers/auth.controller';
import { UserRepository } from '../repositories';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './schemas/auth.schema';
import { RefreshTokenRepository } from '../repositories/refresh-token-repository';
import { JwtModule } from '@nestjs/jwt';
import { RefreshToken, RefreshTokenSchema } from './schemas';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { StringValue } from 'ms';

@Module({
  imports: [
    ConfigModule,
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: RefreshToken.name, schema: RefreshTokenSchema },
    ]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (cfg: ConfigService) => ({
        secret: cfg.getOrThrow<string>('JWT_ACCESS_SECRET'),
        signOptions: {
          expiresIn: cfg.getOrThrow<StringValue>('JWT_ACCESS_EXPIRES_IN'),
        },
      }),
    }),
  ],
  providers: [AuthService, UserRepository, RefreshTokenRepository],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
