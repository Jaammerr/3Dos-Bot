from enum import Enum


class APIErrorType(Enum):
    INVALID_CAPTCHA = "Captcha verification failed."
    EMAIL_NOT_VERIFIED = "Your email address is not verified."
    API_KEY_ALREADY_GENERATED = "Api key is already generated for this account"
    UNAUTHENTICATED = "Unauthenticated."


class APIError(Exception):
    def __init__(self, error: str, response_data: dict = None):
        self.error = error
        self.response_data = response_data
        self.error_type = self._get_error_type()
        super().__init__(error)

    def _get_error_type(self) -> APIErrorType | None:
        return next(
            (error_type for error_type in APIErrorType if error_type.value == self.error_message),
            None
        )

    @property
    def error_message(self) -> str:
        if self.response_data and "message" in self.response_data:
            return self.response_data["message"]
        elif self.response_data and "error" in self.response_data:
            return self.response_data["error"]
        return self.error

    def __str__(self):
        return self.error



class SessionRateLimited(Exception):
    """Raised when the session is rate limited"""

    pass


class CaptchaSolvingFailed(Exception):
    """Raised when the captcha solving failed"""

    pass


class ServerError(Exception):
    """Raised when the server returns an error"""

    pass


class NoAvailableProxies(Exception):
    """Raised when there are no available proxies"""

    pass


class ProxyForbidden(Exception):
    """Raised when the proxy is forbidden"""

    pass


class EmailValidationFailed(Exception):
    """Raised when the email validation failed"""

    pass

