import {
  createParamDecorator,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';

export const CookieRefreshToken = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const refreshToken = request?.cookies.refresh_token;
    console.info(`Extracted refresh token from cookies`);
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }

    return refreshToken;
  },
);
