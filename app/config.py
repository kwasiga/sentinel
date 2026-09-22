"""Environment-based application configuration."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite+pysqlite:///:memory:"
    REDIS_URL: str = ""
    AUTH_SECRET: str = "development-only-change-me"
    AUTH_TOKEN_TTL_SECONDS: int = 3600
    BOOTSTRAP_USERNAME: str = ""
    BOOTSTRAP_PASSWORD: str = ""
    BRUTE_FORCE_THRESHOLD: int = 5
    BRUTE_FORCE_WINDOW_SECONDS: int = 60


settings = Settings()
