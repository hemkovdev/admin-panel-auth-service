import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly configService: ConfigService) {
    const publicKey = configService.get<string>('JWT_ACCESS_PUBLIC_KEY');

    if (!publicKey) {
      throw new Error('JWT_ACCESS_PUBLIC_KEY is missing');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,

      secretOrKey: Buffer.from(publicKey, 'base64'),

      algorithms: ['RS256'],
      issuer: 'auth-service',
      audience: 'web-client',
    });
  }

  async validate(payload: any) {
    return {
      user_id: payload.sub,
      role: payload.role,
    };
  }
}
