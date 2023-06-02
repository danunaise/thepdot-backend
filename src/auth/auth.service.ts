import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from './utils/constants';
import { signinDto } from './dto/signin.dto';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) { }

  async signup(dto: AuthDto) {
    const { email, username, password } = dto;

    const foundEmail = await this.prisma.users.findUnique({ where: { email } });
    if (foundEmail) throw new Error('email already exists');

    const hashedPassword = await this.hashPassword(password);
    await this.prisma.users.create({
      data: {
        email,
        username,
        password: hashedPassword,
      },
    });
    return { message: 'signup was succefull' };
  }

  async signin(dto: AuthDto, req: Request, res: Response) {
    const { email, password } = dto;
    const foundUser = await this.prisma.users.findUnique({ where: { email } });

    if (!foundUser) {
      throw new Error('worng email or password');
    }

    const isMatch = await this.comparePassword(password, foundUser.password);
    if (!isMatch) {
      throw new Error('worng email or password');
    }

    const token = await this.signToken(foundUser.id, foundUser.email);
    if (!token) {
      throw new ForbiddenException('token not found');
    }

    res.cookie('token', token);
    return res.send({ message: 'signin was succefully' });
  }

  async signout(req: Request, res: Response) {
    res.clearCookie('token');
    return res.send({ message: 'signout was succefully' });
  }

  async hashPassword(password: string) {
    const saltOrRounds = 10;
    return await bcrypt.hash(password, saltOrRounds);
  }

  async comparePassword(password: string, hash: string) {
    return await bcrypt.compare(password, hash);
  }

  async signToken(id: any, email: any) {
    const payload = { id, email };
    const token = await this.jwt.signAsync(payload, {
      secret: jwtSecret,
      expiresIn: '10s',
    });
    return token;
    //eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZW1haWwiOiJhZG1pbkB0ZXN0LmNvbSIsImlhdCI6MTY4NTY0NDIxMywiZXhwIjoxNjg1NzMwNjEzfQ.lw2SQpwjbMp3mWwDu-hqXhS1y0zLrq1aSK1kWCrus_Y
  }
}
