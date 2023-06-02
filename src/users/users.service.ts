import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { Request } from 'express';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async getMyUser(id: string, req: Request) {
    const numericId = parseInt(id, 10);
    const decodedUserInfo = req.user as { id: number; email: string };
    const foundUser = await this.prisma.users.findUnique({
      where: { id: numericId },
    });

    if (!foundUser) {
      throw new NotFoundException();
    }

    if (foundUser.id !== decodedUserInfo.id) {
      throw new ForbiddenException();
    }

    if (foundUser.password) {
      delete foundUser.password;
    }

    return { user: foundUser };
  }

  async getAllUsers() {
    return await this.prisma.users.findMany({
      select: { id: true, email: true, username: true },
    });
  }
}
