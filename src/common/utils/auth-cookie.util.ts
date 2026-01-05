import { Response } from 'express';

export const setRefreshTokenCookie = (
  res: Response,
  refresh_token: string,
) => {
  res.cookie('refresh_token', refresh_token, {
    httpOnly: process.env.NODE_ENV === 'production' ? true: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/v2/auth/refresh-token',
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  });
};
