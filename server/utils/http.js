export function httpError(message, statusCode = 400, details = null) {
    const error = new Error(message);
    error.statusCode = statusCode;
    if (details) error.details = details;
    return error;
}

export function sendError(res, error, fallbackStatus = 500) {
    const status = error.statusCode || fallbackStatus;
    const body = {
        success: false,
        error: error.message || 'Unexpected error'
    };

    if (error.details) {
        body.details = error.details;
    }

    res.status(status).json(body);
}

