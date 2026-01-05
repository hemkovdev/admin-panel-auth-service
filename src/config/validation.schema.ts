import * as Joi from 'joi';

export const validationSchema = Joi.object({
  // === Database ===
  DB_HOST: Joi.string().default('localhost'),
  DB_PORT: Joi.number().default(27017),
  DB_USERNAME: Joi.string().allow(''), // optional
  DB_PASSWORD: Joi.string().allow(''), // optional
  DB_NAME: Joi.string().default('Cart'),
  DB_SYNCHRONIZE: Joi.boolean().default(false),
  DB_LOGGING: Joi.boolean().default(false),
  DB_SSL: Joi.boolean().default(false),
});
