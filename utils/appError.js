// for all errors

class AppError extends Error
{
    constructor(message,statusCode)
    {
        super(message);
        this.statusCode = statusCode;
        this.status = `${statusCode}`.at(0) === '4' ? 'fail' : 'error';
        //will allow checking if error is progamer's mistake or not
        this.isOperational = true;

        Error.captureStackTrace(this, this.constructor);
    }
}

module.exports = AppError;