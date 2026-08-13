"""Error types raised by the EIP API client."""

from __future__ import annotations


class ApiError(Exception):
    """Base class for every EIP API failure."""


class ApiNotFound(ApiError):
    """The requested vulnerability or artifact does not exist."""


class ApiInvalidRequest(ApiError):
    """The API rejected the request parameters."""


class ApiUnavailable(ApiError):
    """The API, its read model, or a subsystem is unavailable."""
