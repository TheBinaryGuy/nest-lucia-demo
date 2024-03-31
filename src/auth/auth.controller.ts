import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Post('login')
  async signIn(
    @Req() req: Request,
    @Res({ passthrough: true }) response: Response,
    @Body() signInDto: Record<string, any>,
  ) {
    const cookie = await this.authService.signIn(
      signInDto.username,
      signInDto.password,
    );

    response.setHeader('Set-Cookie', cookie);

    return { message: 'User signed in' };
  }

  @HttpCode(HttpStatus.OK)
  @Post('register')
  async register(
    @Res({ passthrough: true }) response: Response,
    @Body() registerDto: Record<string, any>,
  ) {
    const cookie = await this.authService.register(
      registerDto.username,
      registerDto.password,
    );

    response.setHeader('Set-Cookie', cookie);

    return { message: 'User registered' };
  }
}
