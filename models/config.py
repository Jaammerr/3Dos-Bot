import secrets
import string
import random

from dataclasses import dataclass
from pydantic import BaseModel, PositiveInt, ConfigDict, Field


class BaseConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)


@dataclass
class RedirectConfig:
    enabled: bool
    email: str = ""
    password: str = ""
    imap_server: str = ""
    use_proxy: bool = False


class Account(BaseConfig):
    email: str
    password: str = ""
    account_password: str = ""
    imap_server: str = ""


@dataclass
class CaptchaSettings:
    solvium_api_key: str = ""
    max_captcha_solving_time: PositiveInt = 60
    proxy: str = ""


@dataclass
class Range:
    min: int
    max: int


@dataclass
class AttemptsAndDelaySettings:
    delay_before_start: Range
    error_delay: PositiveInt

    max_register_attempts: PositiveInt
    max_reverify_attempts: PositiveInt
    max_login_attempts: PositiveInt
    max_stats_attempts: PositiveInt
    max_captcha_attempts: PositiveInt
    max_farm_attempts: PositiveInt


@dataclass
class IMAPSettings:

    @dataclass
    class UseSingleImap:
        enable: bool
        imap_server: str = ""

    use_single_imap: UseSingleImap
    use_proxy_for_imap: bool

    servers: dict[str, str]


@dataclass
class ApplicationSettings:
    threads: PositiveInt
    farm_delay: PositiveInt
    database_url: str
    skip_logged_accounts: bool
    shuffle_accounts: bool
    check_uniqueness_of_proxies: bool
    gen_random_pass_for_accounts: bool
    use_ref_codes_from_database: bool


class Config(BaseConfig):
    accounts_to_register: list[Account] = Field(default_factory=list)
    accounts_to_farm: list[Account] = Field(default_factory=list)
    accounts_to_login: list[Account] = Field(default_factory=list)
    accounts_to_export_stats: list[Account] = Field(default_factory=list)
    accounts_to_complete_tasks: list[Account] = Field(default_factory=list)
    accounts_to_verify: list[Account] = Field(default_factory=list)

    referral_codes: list[str] = Field(default_factory=list)
    proxies: list[str] = Field(default_factory=list)

    application_settings: ApplicationSettings
    attempts_and_delay_settings: AttemptsAndDelaySettings
    captcha_settings: CaptchaSettings
    redirect_settings: RedirectConfig
    imap_settings: IMAPSettings

    module: str = ""
