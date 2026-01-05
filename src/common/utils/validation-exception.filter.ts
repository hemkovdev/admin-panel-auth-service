import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  BadRequestException,
} from '@nestjs/common';

@Catch(BadRequestException)
export class ValidationExceptionFilter implements ExceptionFilter {
  catch(exception: BadRequestException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();
    const status = exception.getStatus();

    const exceptionResponse = exception.getResponse() as any;

    let message = 'Invalid request';

    if (Array.isArray(exceptionResponse?.message)) {
      message = exceptionResponse.message[0];
    }

    response.status(status).json({
      meta: {
        request_id: 'req_' + Date.now(),
        timestamp: new Date().toISOString(),
        version: 'v1',
      },
      error: {
        code: 'INVALID_REQUEST',
        message,
      },
    });
  }
}
