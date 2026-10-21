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
    PORT_SCAN_THRESHOLD: int = 10
    PORT_SCAN_WINDOW_SECONDS: int = 60
    PASSWORD_SPRAY_THRESHOLD: int = 5
    PASSWORD_SPRAY_WINDOW_SECONDS: int = 60
    PASSWORD_SPRAY_MIN_ACCOUNTS: int = 5
    SUSPICIOUS_IAM_ACTIONS: str = "CreateAccessKey,AttachUserPolicy,PutUserPolicy,CreateLoginProfile,UpdateAssumeRolePolicy"
    RISK_MEDIUM_THRESHOLD: int = 30
    RISK_HIGH_THRESHOLD: int = 60
    RISK_CRITICAL_THRESHOLD: int = 85


settings = Settings()
