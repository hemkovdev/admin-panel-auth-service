import { Body, Controller, Get, Post, Req, Res } from '@nestjs/common';
import { AuthService } from '../services/auth.service';
import {
  ApiBearerAuth,
  ApiCookieAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { LoginDto, SignUpDto } from '../dtos';
import type { Request, Response } from 'express';
import { CookieRefreshToken } from '../decorators';
import { setRefreshTokenCookie } from 'src/common/utils';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // REGISTER USER
  @Post('signup')
  @ApiOperation({ summary: 'Register a new User' })
  @ApiResponse({ status: 201, description: 'User registered successfully' })
  signup(@Body() dto: SignUpDto) {
    return this.authService.signup(dto);
  }

  // LOGIN USER
  @Post('login')
  @ApiOperation({
    summary: 'Login user',
    description:
      'Authenticates a user using email and password. Returns an access token in the response and sets the refresh token in an HttpOnly cookie.',
  })
  @ApiResponse({
    status: 200,
    description: 'Login successful',
  })
  @ApiResponse({
    status: 400,
    description:
      'Email or password format is invalid. Please verify and try again.',
  })
  @ApiResponse({
    status: 401,
    description: 'Incorrect email or password. Please verify and try again.',
  })
  @ApiResponse({
    status: 403,
    description: `You don't have permission to access this application.`,
  })
  @ApiResponse({
    status: 408,
    description: 'The server took too long to respond. Please try again.',
  })
  @ApiResponse({
    status: 503,
    description:
      'The service is temporarily unavailable. Please try again later.',
  })
  @ApiResponse({
    status: 500,
    description: 'An unexpected error occurred. Please try again.',
  })
  async login(
    @Res({ passthrough: true }) res: Response,
    @Body() dto: LoginDto,
  ) {
    const result = await this.authService.login(dto);

    setRefreshTokenCookie(res, result.refresh_token);

    return {
      meta: {
        request_id: 'req_' + Date.now(),
        timestamp: new Date().toISOString(),
        version: 'v2',
        end_point: '/api/v2/auth/login',
      },
      user: result.user,
      auth: result.auth,
    };
  }

  // REFRESH TOKEN
  @Post('refersh-token')
  @ApiCookieAuth('refresh_token')
  @ApiOperation({ summary: 'Refresh access token using refresh token cookie' })
  @ApiResponse({ status: 200, description: 'Token refreshed successfully' })
  @ApiResponse({ status: 401, description: 'Invalid or missing refresh token' })
  async refresh(
    @Res({ passthrough: true }) res: Response,
    @CookieRefreshToken() refresh_token: string,
  ) {
    const result = await this.authService.refreshToken(refresh_token);

    setRefreshTokenCookie(res, refresh_token);

    return {
      auth: result.auth,
    };
  }

  // LOGOUT
  @Post('logout')
  @ApiCookieAuth('refresh_token')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout user' })
  logout(@CookieRefreshToken() refresh_token: string) {
    this.authService.logout(refresh_token);
  }

  // ME
  // @Get('me')
  // @ApiBearerAuth()
  // @ApiOperation({ summary: 'Get current user' })
  // me(@Req() req: Request) {
  //   return this.authService.me(req);
  // }
}
