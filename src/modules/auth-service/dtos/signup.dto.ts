import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsIn,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
  MinLength,
} from 'class-validator';

export class SignUpDto {
  @ApiProperty({
    example: 'Rahul Sharma',
    description: 'Full name of the user',
  })
  @IsString()
  @IsNotEmpty()
  full_name: string;

  @ApiProperty({
    example: 'user@thirdwavecoffee.in',
    description: 'Registeered email address',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: 'Password@123',
    description:
      'Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character',
  })
  @IsString()
  @MinLength(8)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/, {
    message:
      'Password must include uppercase, lowercase, number, and special character',
  })
  password: string;

  @ApiProperty({
    example: 'USER',
    description: 'Role assigned to user',
    enum: ['USER', 'ADMIN'],
    required: false,
  })
  @IsOptional()
  @IsIn(['USER', 'ADMIN'])
  role: string;
}
