"""Helper utilities for lazy-initialised analysis engines."""

from __future__ import annotations

from typing import Callable, Generic, Optional, Protocol, TypeVar

T = TypeVar("T")


class SupportsShutdown(Protocol):
    """Protocol describing analyzers that expose shutdown hooks."""

    def shutdown_executor(self) -> None:
        ...


class LazyAnalyzer(Generic[T]):
    """Wrap an analyzer factory to allow lazy initialisation and shutdown."""

    def __init__(
        self,
        factory: Callable[[], T],
        shutdown: Optional[Callable[[T], None]] = None,
    ) -> None:
        self._factory = factory
        self._shutdown = shutdown
        self._instance: Optional[T] = None

    def get(self) -> T:
        if self._instance is None:
            self._instance = self._factory()
        return self._instance

    @property
    def is_initialised(self) -> bool:
        return self._instance is not None

    def shutdown(self) -> None:
        if self._instance is None:
            return
        if self._shutdown:
            self._shutdown(self._instance)
        else:
            shutdown_fn = getattr(self._instance, "shutdown_executor", None)
            if callable(shutdown_fn):
                shutdown_fn()
        self._instance = None
