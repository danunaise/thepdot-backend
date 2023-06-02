import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class AuthDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  username: string;

  @IsNotEmpty()
  @IsString()
  @Length(8, 20, { message: 'password must be between 8 and 20 characters' })
  password: string;
}
