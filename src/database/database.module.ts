import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import databaseConfig from 'src/config/database.config';

const buildMongoUri = (cfg: ConfigService): string => {
  const host = cfg.get<string>('database.host')!;
  const port = cfg.get<number>('database.port')!;
  const dbName = cfg.get<string>('database.database')!;
  const username = cfg.get<string | undefined>('database.username');
  const password = cfg.get<string | undefined>('database.password');

//   if (username && password) {
//     return `mongodb://${encodeURIComponent(username)}:${encodeURIComponent(password)}@${host}:${port}/${dbName}`;
//   }
  return `mongodb://${host}:${port}/${dbName}`;
};

@Module({
  imports: [
    ConfigModule.forFeature(databaseConfig),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (cfg: ConfigService) => ({
        uri: buildMongoUri(cfg),
        ssl: cfg.get<boolean>('database.ssl', false),
      }),
    }),
  ],
})
export class DatabaseModule {}
