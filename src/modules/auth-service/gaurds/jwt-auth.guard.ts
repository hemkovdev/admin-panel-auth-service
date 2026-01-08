import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}


// @UseGuards(JwtAuthGuard)
// @Get('me')
// me(@Req() req) {
//   return req.user; // set by JwtStrategy.validate()
// }