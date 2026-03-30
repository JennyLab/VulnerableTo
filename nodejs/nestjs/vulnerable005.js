/*
    NestJS: Vulnerable to Parameter Pollution 

    

*/

import { Controller, Get, Query } from '@nestjs/common';
import { IsString, MinLength } from 'class-validator';

export class SearchDto {
  @IsString()
  @MinLength(3)
  term: string;
}

@Controller('search')
export class SearchController {
  @Get()
  async search(@Query() query: SearchDto) {
    // Si se envía ?term=abc&term=def, 'term' es ['abc', 'def']
    // Algunas librerías de DB procesarán esto como un operador "IN"
    return `Searching for: ${query.term}`;
  }
}
