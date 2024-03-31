import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class AuthService {
  private client = new PrismaClient();

  private async getLucia() {
    const { Lucia } = await import('lucia');
    const { PrismaAdapter } = await import('@lucia-auth/adapter-prisma');
    const adapter = new PrismaAdapter(this.client.session, this.client.user);
    return new Lucia<Record<never, never>, { username: string }>(adapter, {
      sessionCookie: {
        attributes: {
          secure: process.env.NODE_ENV === 'production',
        },
      },
      getUserAttributes: (attributes: { username: string }) => {
        return {
          username: attributes.username,
        };
      },
    });
  }

  private async hashPassword(password: string) {
    const { Argon2id } = await import('oslo/password');
    const passwordHash = await new Argon2id().hash(password);
    return passwordHash;
  }

  private async verifyHash(password: string, hash: string) {
    const { Argon2id } = await import('oslo/password');
    return await new Argon2id().verify(hash, password);
  }

  private async generateId() {
    const { generateId } = await import('lucia');
    return generateId(15);
  }

  async signIn(username: string, pass: string): Promise<string> {
    const lucia = await this.getLucia();

    const user = await this.client.user.findUnique({
      where: {
        username,
      },
    });

    if (!user) {
      throw new UnauthorizedException();
    }

    const hashVerified = await this.verifyHash(pass, user.passwordHash);
    if (!hashVerified) {
      throw new UnauthorizedException();
    }

    const session = await lucia.createSession(user.id, {});
    return lucia.createSessionCookie(session.id).serialize();
  }

  async register(username: string, pass: string): Promise<string> {
    const user = await this.client.user.findUnique({
      where: {
        username,
      },
    });

    if (user) {
      throw new BadRequestException();
    }

    const userId = await this.generateId();
    const passwordHash = await this.hashPassword(pass);

    const newUser = await this.client.user.create({
      data: {
        id: userId,
        username,
        passwordHash,
      },
    });

    const lucia = await this.getLucia();
    const session = await lucia.createSession(newUser.id, {});
    return lucia.createSessionCookie(session.id).serialize();
  }
}
