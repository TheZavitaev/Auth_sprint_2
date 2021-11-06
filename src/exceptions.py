from flask import Response, make_response
from pydantic import ValidationError
from werkzeug.exceptions import BadRequest, HTTPException, Unauthorized


class RequestValidationError(HTTPException):
    code = 400

    def __init__(self, e: ValidationError):
        self.response = Response(status=self.code, response=str(e))


class AlreadyExistsError(HTTPException):
    code = 409


class AuthenticationError(Unauthorized):
    def __init__(self):
        super().__init__(www_authenticate='Bearer')


class TokenError(Unauthorized):
    def __init__(self, error, error_description):
        super().__init__(
            response=make_response(
                {'error': error, 'error_description': error_description}, self.code
            )
        )


class PasswordAuthenticationError(BadRequest):
    def __init__(self):
        super().__init__(description='User not found or password is invalid')
