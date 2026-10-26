"""Runtime configuration, read from environment variables (see .env.example)."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SECURESCOPE_", extra="ignore")

    database_url: str = "sqlite:///./data/securescope.db"
    #: Signs session cookies. Must be set to a long random value outside development.
    secret_key: str = Field(default="dev-only-insecure-key-change-me", min_length=16)
    #: "development" allows the default secret key; anything else refuses to start without one.
    environment: str = "development"
    #: Demo mode shows one-click demo sign-in and lets admins reset the data.
    demo_mode: bool = True
    #: Password given to the seeded demo accounts.
    demo_password: str = Field(default="securescope-demo", min_length=8)
    session_max_age_seconds: int = 8 * 60 * 60
    #: Failed sign-ins allowed per account per window before a temporary lockout.
    login_max_failures: int = 5
    login_window_seconds: int = 15 * 60

    @property
    def is_production(self) -> bool:
        return self.environment != "development"


@lru_cache
def get_settings() -> Settings:
    return Settings()
