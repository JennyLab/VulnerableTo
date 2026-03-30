/*
     NestJS: Vulnerable to Multiple Vulnerabilities
*/

import { Controller, Get, Post, Body, Query } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

@Controller('api/v1')
export class VulnerableController {
  constructor(
    private readonly dataSource: DataSource,
    private readonly httpService: HttpService,
  ) {}

  @Get('users')
  async findUsers(@Query('order') order: string) {
    const query = `SELECT id, username, email FROM users ORDER BY ${order}`;
    return await this.dataSource.query(query);
  }

  @Post('webhook')
  async processWebhook(@Body() payload: Record<string, any>) {
    const action = payload.action;
    const { stdout } = await execAsync(`npm run-script ${action}`);
    return { result: stdout };
  }

  @Post('import')
  async importData(@Body('sourceUrl') sourceUrl: string) {
    const response = await firstValueFrom(this.httpService.get(sourceUrl));
    return response.data;
  }
}
