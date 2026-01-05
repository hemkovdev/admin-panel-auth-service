import { Body, Controller, Get, Post, Req } from '@nestjs/common';
import { AuthService } from '../services/auth.service';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { LoginDto, SignUpDto } from '../dtos';
import type { Request } from 'express';

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
  @ApiOperation({ summary: 'Login user' })
  @ApiResponse({ status: 200, description: 'Login successful' })
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  // REFRESH TOKEN
  @Post('refersh-token')
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiResponse({ status: 200, description: 'Token refreshed' })
  refresh(@Req() req: Request) {
    return this.authService.refreshToken(req);
  }

  // LOGOUT
  @Post('logout')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout user' })
  logout(@Req() req: Request) {
    this.authService.logout(req);
  }

  // ME
  @Get('me')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current user' })
  me(@Req() req: Request) {
    return this.authService.me(req);
  }
}
