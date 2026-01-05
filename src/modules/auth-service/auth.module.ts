import { Module } from '@nestjs/common';
import { AuthService } from './services/auth.service';
import { AuthController } from './controllers/auth.controller';
import { UserRepository } from '../repositories';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './schemas/auth.schema';
import { RefreshTokenRepository } from '../repositories/refresh-token-repository';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken, RefreshTokenSchema } from './schemas';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: RefreshToken.name, schema: RefreshTokenSchema },
    ]),
  ],
  providers: [AuthService, UserRepository, RefreshTokenRepository, JwtService],
  controllers: [AuthController],
})
export class AuthModule {}
