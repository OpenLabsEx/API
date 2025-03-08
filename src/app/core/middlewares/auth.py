from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint


async def auth_exception_middleware(
    request: Request,
    call_next: RequestResponseEndpoint,
    router_prefix: str,
) -> Response:
    """Middleware to handle auth-related ValueErrors thrown by auth functions.

    Only converts ValueErrors to HTTP responses if:
    1. The error message starts with "auth:"
    2. The request is to an API route (starts with router_prefix)

    Args:
        request: The FastAPI request object
        call_next: The next middleware/endpoint to call
        router_prefix: The API router prefix to scope this middleware to

    Returns:
        The response from the next middleware/endpoint

    """
    try:
        # Process the request normally
        return await call_next(request)
    except ValueError as exc:
        # Only handle ValueErrors if they're from auth and we're in an API route
        error_str = str(exc)

        if error_str.startswith("auth:"):
            parts = error_str.split(":", 2)
            # Expected format is "auth:type:detail"
            required_parts = 3
            if len(parts) >= required_parts:
                error_type, error_detail = parts[1], parts[2]

                # Map error types to status codes
                status_codes = {
                    "missing_credentials": status.HTTP_401_UNAUTHORIZED,
                    "invalid_credentials": status.HTTP_401_UNAUTHORIZED,
                    "no_expiration": status.HTTP_401_UNAUTHORIZED,
                    "expired": status.HTTP_401_UNAUTHORIZED,
                    "user_not_found": status.HTTP_401_UNAUTHORIZED,
                    "invalid_token": status.HTTP_401_UNAUTHORIZED,
                    "forbidden": status.HTTP_403_FORBIDDEN,
                }

                status_code = status_codes.get(
                    error_type, status.HTTP_500_INTERNAL_SERVER_ERROR
                )

                # Add WWW-Authenticate header for 401 responses
                headers = {}
                if status_code == status.HTTP_401_UNAUTHORIZED:
                    headers["WWW-Authenticate"] = "Bearer"

                return JSONResponse(
                    status_code=status_code,
                    content={"detail": error_detail},
                    headers=headers,
                )
        # For non-auth ValueErrors or if we're not in an API route, re-raise
        raise exc
