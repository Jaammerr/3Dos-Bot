import asyncio
import random

from datetime import datetime, timezone
from typing import Literal
from better_proxy import Proxy
from loguru import logger

from loader import config, file_operations, captcha_solver, proxy_manager
from models import Account, OperationResult

from core.api._3dos import _3dosAPI
from utils import EmailValidator, LinkExtractor, operation_failed, operation_success, handle_sleep, generate_password
from database import Accounts
from core.exceptions.base import APIError, SessionRateLimited, CaptchaSolvingFailed, APIErrorType, ProxyForbidden, EmailValidationFailed
from core.exceptions.validator import validate_error
from utils.base.datetime_utils import get_sleep_until


class Bot:
    def __init__(self, account_data: Account):
        self.account_data = account_data

    @staticmethod
    async def handle_invalid_account(
            email: str,
            email_password: str = None,
            account_password: str = None,
            reason: Literal["unverified", "banned", "unregistered", "unlogged"] = None,
            log: bool = True
    ) -> None:
        if reason == "unverified":
            if log:
                logger.error(f"Account: {email} | Email not verified, run <<Verify accounts>> module | Removed from list")
            await file_operations.export_invalid_account(email, email_password, account_password, "unverified")

        elif reason == "banned":
            if log:
                logger.error(f"Account: {email} | Account is banned | Removed from list")
            await file_operations.export_invalid_account(email, email_password, account_password, "banned")

        elif reason == "unregistered":
            if log:
                logger.error(f"Account: {email} | Email not registered, run <<Register accounts>> module | Removed from list")
            await file_operations.export_invalid_account(email, email_password, account_password, "unregistered")

        elif reason == "unlogged":
            if log:
                logger.error(f"Account: {email} | Account not logged in, run <<Login accounts>> module | Removed from list")
            await file_operations.export_invalid_account(email, email_password, account_password, "unlogged")

        for account in config.accounts_to_farm:
            if account.email == email:
                config.accounts_to_farm.remove(account)

    async def _validate_email(self, proxy: str = None) -> dict:
        proxy = Proxy.from_str(proxy) if proxy else None

        if config.redirect_settings.enabled:
            result = await EmailValidator(
                config.redirect_settings.imap_server,
                config.redirect_settings.email,
                config.redirect_settings.password
            ).validate(None if config.imap_settings.use_proxy_for_imap is False else proxy)
        else:
            result = await EmailValidator(
                self.account_data.imap_server,
                self.account_data.email,
                self.account_data.password
            ).validate(None if config.imap_settings.use_proxy_for_imap is False else proxy)

        return result

    async def _is_email_valid(self, proxy: str = None) -> bool:
        result = await self._validate_email(proxy)
        if not result["status"]:
            if "validation failed" in result["data"]:
                raise EmailValidationFailed(f"Email validation failed: {result['data']}")

            logger.error(f"Account: {self.account_data.email} | Email is invalid: {result['data']}")
            return False

        return True

    async def _extract_link(self, proxy: str = None) -> dict:
        if config.redirect_settings.enabled:
            confirm_url = await LinkExtractor(
                imap_server=config.redirect_settings.imap_server,
                email=config.redirect_settings.email,
                password=config.redirect_settings.password,
                redirect_email=self.account_data.email
            ).extract_link(None if config.imap_settings.use_proxy_for_imap is False else proxy)
        else:
            confirm_url = await LinkExtractor(
                imap_server=self.account_data.imap_server,
                email=self.account_data.email,
                password=self.account_data.password,
            ).extract_link(None if config.imap_settings.use_proxy_for_imap is False else proxy)

        return confirm_url

    async def _update_account_proxy(self, account_data: Accounts, attempt: int | str) -> None:
        max_attempts = config.attempts_and_delay_settings.max_register_attempts if config.module == "registration" else config.attempts_and_delay_settings.max_login_attempts if config.module == "login" else config.attempts_and_delay_settings.max_stats_attempts if config.module == "export_stats" else config.attempts_and_delay_settings.max_reverify_attempts if config.module == "verify" else config.attempts_and_delay_settings.max_farm_attempts

        proxy_changed_log = (
            f"Account: {self.account_data.email} | Proxy changed | "
            f"Retrying in {config.attempts_and_delay_settings.error_delay}s.. | "
            f"Attempt: {attempt + 1}/{max_attempts}.."
        )

        if not account_data:
            logger.info(proxy_changed_log)
            await asyncio.sleep(config.attempts_and_delay_settings.error_delay)
            return

        if account_data.active_account_proxy:
            await proxy_manager.release_proxy(account_data.active_account_proxy)

        proxy = await proxy_manager.get_proxy()
        await account_data.update_account_proxy(proxy.as_url if isinstance(proxy, Proxy) else proxy)

        logger.info(proxy_changed_log)
        await asyncio.sleep(config.attempts_and_delay_settings.error_delay)

    async def get_captcha_data(self, proxy: str) -> tuple[bool, str] | None:
        max_attempts = config.attempts_and_delay_settings.max_captcha_attempts

        async def handle_recaptcha() -> tuple[bool, str]:
            logger.info(f"Account: {self.account_data.email} | Solving captcha...")

            success, answer = await captcha_solver.solve_recaptcha(
                page_url="https://dashboard.3dos.io/register",
                site_key="6Lfp7N8qAAAAAGzZkHCJXV7mCHX25VuEeE1dh5Md",
                action="yourAction",
                proxy=proxy
            )

            if success:
                logger.success(f"Account: {self.account_data.email} | Captcha solved")
                return success, answer

            raise ValueError(f"Failed to solve captcha challenge: {answer}")

        handler = handle_recaptcha
        for attempt in range(max_attempts):
            try:
                return await handler()
            except Exception as e:
                logger.error(
                    f"Account: {self.account_data.email} | Error occurred while solving captcha: {str(e)} | Retrying..."
                )
                if attempt == max_attempts - 1:
                    raise CaptchaSolvingFailed(f"Failed to solve captcha after {max_attempts} attempts")

    @staticmethod
    async def _prepare_account_proxy(db_account_value: Accounts) -> str:
        if db_account_value and db_account_value.active_account_proxy:
            proxy = db_account_value.active_account_proxy
            if not proxy:
                proxy = await proxy_manager.get_proxy()
                await db_account_value.update_account(proxy=proxy.as_url if isinstance(proxy, Proxy) else proxy)
        else:
            proxy = await proxy_manager.get_proxy()

        return proxy.as_url if isinstance(proxy, Proxy) else proxy

    async def _save_account(
            self,
            db_account_value: Accounts,
            proxy: str,
            access_token: str,
            sui_address: str,
            referral_code: str,
            api_secret: str = None
    ) -> None:
        if db_account_value:
            await db_account_value.update_account(
                email_password=self.account_data.password,
                account_password=self.account_data.account_password,
                access_token=access_token,
                sui_address=sui_address,
                proxy=proxy,
                referral_code=referral_code,
                api_secret=api_secret,
            )
        else:
            await Accounts.create(
                email=self.account_data.email,
                email_password=self.account_data.password,
                account_password=self.account_data.account_password,
                access_token=access_token,
                sui_address=sui_address,
                active_account_proxy=proxy,
                referral_code=referral_code,
                api_secret=api_secret,
            )

    async def _confirm_confirmation_url(self, api: _3dosAPI) -> bool:
        confirm_url = await self._extract_link()
        if not confirm_url["status"]:
            return False

        url = confirm_url["data"]
        await api.clear_request(url)
        return True

    async def _register_account(self, api: _3dosAPI) -> dict:
        solved, captcha_token = await self.get_captcha_data(api.proxy)
        if config.application_settings.use_ref_codes_from_database:
            referral_code = await Accounts.get_random_invite_code()
            if referral_code:
                logger.info(f"Account: {self.account_data.email} | Using random referral code from database: {referral_code}")
        else:
            referral_code = random.choice(config.referral_codes) if config.referral_codes else None
            if referral_code:
                logger.info(f"Account: {self.account_data.email} | Using random referral code from file: {referral_code}")

        return await api.register(
            email=self.account_data.email,
            password=self.account_data.account_password,
            captcha_token=captcha_token,
            referred_by=referral_code,
        )

    async def _login_account(self, api: _3dosAPI, email: str = None, password: str = None) -> str:
        solved, captcha_token = await self.get_captcha_data(api.proxy)
        if not email or not password:
            return await api.login(
                email=self.account_data.email,
                password=self.account_data.account_password,
                captcha_token=captcha_token,
            )
        else:
            return await api.login(
                email=email,
                password=password,
                captcha_token=captcha_token,
            )

    async def process_registration(self) -> OperationResult | None:
        max_attempts = config.attempts_and_delay_settings.max_register_attempts
        last_completed_action = None

        for attempt in range(max_attempts):
            db_account_value, api, registration_data, access_token = None, None, None, None

            try:
                db_account_value = await Accounts.get_account(email=self.account_data.email)
                if db_account_value and db_account_value.access_token:
                    logger.warning(f"Account: {db_account_value.email} | Account already logged in, skipped")
                    return operation_success(db_account_value.email, db_account_value.email_password, db_account_value.account_password)

                logger.info(f"Account: {self.account_data.email} | Registering | Attempt: {attempt + 1}/{max_attempts}..")
                proxy = await self._prepare_account_proxy(db_account_value)
                api = _3dosAPI(proxy=proxy)

                if last_completed_action is None:
                    if not await self._is_email_valid(proxy):
                        return operation_failed(email=self.account_data.email, email_password=self.account_data.password)

                    last_completed_action = "email_validation"

                if last_completed_action == "email_validation":
                    logger.info(f"Account: {self.account_data.email} | Email is valid, registering...")
                    if not self.account_data.account_password:
                        self.account_data.account_password = generate_password(random.randint(12, 16)) if config.application_settings.gen_random_pass_for_accounts else self.account_data.password

                    registration_data = await self._register_account(api=api)
                    logger.success(f"Account: {self.account_data.email} | Confirmation email sent")
                    last_completed_action = "registration"

                if last_completed_action == "registration":
                    if not await self._confirm_confirmation_url(api=api):
                        logger.error(f"Account: {self.account_data.email} | Confirmation link not found | Exported to <<unverified_accounts.txt>>")

                        await self.handle_invalid_account(self.account_data.email, self.account_data.password, self.account_data.account_password, "unverified", log=False)
                        return None

                    last_completed_action = "confirmation_code"

                if last_completed_action == "confirmation_code":
                    logger.info(f"Account: {self.account_data.email} | Registration verified and completed, logging in..")
                    access_token = await api.login(email=self.account_data.email, password=self.account_data.account_password)

                await self._save_account(
                    db_account_value=db_account_value,
                    proxy=proxy,
                    access_token=access_token,
                    sui_address=registration_data["sui_address"],
                    referral_code=registration_data["referral_code"],
                )

                logger.success(f"Account: {self.account_data.email} | Logged in | Session saved to database")
                return operation_success(self.account_data.email, self.account_data.password, self.account_data.account_password)

            except APIError as error:
                if last_completed_action in ("registration", "confirmation_code"):
                    logger.warning(f"Account: {self.account_data.email} | Email registered but not verified, error: {error} | Exported to <<unverified_accounts.txt>>")
                    await self.handle_invalid_account(self.account_data.email, self.account_data.password, self.account_data.account_password, "unverified", log=False)
                    return None

                if error.error_type == APIErrorType.INVALID_CAPTCHA:
                    logger.error(f"Account: {self.account_data.email} | Captcha answer incorrect | Retrying in {config.attempts_and_delay_settings.error_delay} seconds")
                    await asyncio.sleep(config.attempts_and_delay_settings.error_delay)
                    continue

                logger.error(f"Account: {self.account_data.email} | Error occurred during registration (APIError): {error} | Skipped permanently")
                return operation_failed(self.account_data.email, self.account_data.password, self.account_data.account_password)

            except EmailValidationFailed as error:
                if attempt == max_attempts - 1:
                    logger.error(f"Account: {self.account_data.email} | Max attempts reached, unable to register")
                    return operation_failed(self.account_data.email, self.account_data.password, self.account_data.account_password)

                logger.error(f"Account: {self.account_data.email} | {error}")
                await self._update_account_proxy(db_account_value, attempt)

            except CaptchaSolvingFailed:
                logger.error(f"Account: {self.account_data.email} | Skipped registration due to max captcha attempts reached")
                return operation_failed(self.account_data.email, self.account_data.password, self.account_data.account_password)

            except Exception as error:
                is_last_attempt = attempt == max_attempts - 1
                if is_last_attempt:
                    if last_completed_action in ("registration", "confirmation_code"):
                        logger.warning(f"Account: {self.account_data.email} | Email registered but not verified | Exported to <<unverified_accounts.txt>>")

                        await self.handle_invalid_account(self.account_data.email, self.account_data.password, self.account_data.account_password, "unverified", log=False)
                        return None

                    logger.error(f"Account: {self.account_data.email} | Max attempts reached, unable to register")
                    return operation_failed(self.account_data.email, self.account_data.password, self.account_data.account_password)

                logger.error(f"Account: {self.account_data.email} | Error occurred during registration (Generic Exception): {error}")
                await self._update_account_proxy(db_account_value, attempt)

            finally:
                if api:
                    await api.close_session()


    async def process_verification(self) -> OperationResult | None:
        max_attempts = config.attempts_and_delay_settings.max_register_attempts
        last_completed_action = None

        for attempt in range(max_attempts):
            db_account_value, api, access_token = None, None, None

            try:
                db_account_value = await Accounts.get_account(email=self.account_data.email)
                if db_account_value and db_account_value.access_token:
                    access_token = db_account_value.access_token

                logger.info(f"Account: {self.account_data.email} | Verify | Attempt: {attempt + 1}/{max_attempts}..")
                proxy = await self._prepare_account_proxy(db_account_value)
                api = _3dosAPI(proxy=proxy, access_token=access_token)

                if not access_token:
                    access_token = await self._login_account(api=api)
                    api.access_token = access_token

                profile_info = await api.profile_info()
                if profile_info["email_verified_at"] is not None:
                    logger.success(f"Account: {self.account_data.email} | Email already verified")
                    return operation_success(self.account_data.email, self.account_data.password, self.account_data.account_password)

                if last_completed_action is None:
                    if not await self._is_email_valid(proxy):
                        return operation_failed(self.account_data.email, self.account_data.password, self.account_data.account_password)

                    last_completed_action = "email_validation"

                if last_completed_action == "email_validation":
                    logger.info(f"Account: {self.account_data.email} | Email is valid, resending confirmation email...")
                    await api.resend_verify_email()

                    logger.success(f"Account: {self.account_data.email} | Confirmation email sent")
                    last_completed_action = "send_confirmation_email"

                if last_completed_action == "send_confirmation_email":
                    if not await self._confirm_confirmation_url(api=api):
                        logger.error(f"Account: {self.account_data.email} | Confirmation link not found | Skipped permanently")
                        return operation_failed(self.account_data.email, self.account_data.password, self.account_data.account_password)

                await self._save_account(
                    db_account_value=db_account_value,
                    proxy=proxy,
                    access_token=access_token,
                    sui_address=profile_info["sui_address"],
                    referral_code=profile_info["referral_code"],
                    api_secret=profile_info["api_secret"],
                )

                logger.success(f"Account: {self.account_data.email} | Account verified | Session saved to database")
                return operation_success(self.account_data.email, self.account_data.password, self.account_data.account_password)

            except APIError as error:
                logger.error(f"Account: {self.account_data.email} | Error occurred during verification (APIError): {error} | Skipped permanently")
                return operation_failed(self.account_data.email, self.account_data.password, self.account_data.account_password)

            except EmailValidationFailed as error:
                if attempt == max_attempts - 1:
                    logger.error(f"Account: {self.account_data.email} | Max attempts reached, unable to verify")
                    return operation_failed(self.account_data.email, self.account_data.password, self.account_data.account_password)

                logger.error(f"Account: {self.account_data.email} | {error}")
                await self._update_account_proxy(db_account_value, attempt)

            except Exception as error:
                is_last_attempt = attempt == max_attempts - 1
                if is_last_attempt:
                    logger.error(f"Account: {self.account_data.email} | Max attempts reached, unable to verify")
                    return operation_failed(self.account_data.email, self.account_data.password, self.account_data.account_password)

                logger.error(f"Account: {self.account_data.email} | Error occurred during verification (Generic Exception): {error}")
                await self._update_account_proxy(db_account_value, attempt)

            finally:
                if api:
                    await api.close_session()


    async def process_login(self, relogin: bool = False) -> OperationResult | None:
        max_attempts = config.attempts_and_delay_settings.max_register_attempts

        for attempt in range(max_attempts):
            db_account_value = None

            try:
                db_account_value = await Accounts.get_account(email=self.account_data.email)
                if not relogin:
                    if config.application_settings.skip_logged_accounts is True and db_account_value and db_account_value.access_token:
                        logger.warning(f"Account: {self.account_data.email} | Account already logged in, skipped")
                        return operation_success(email=self.account_data.email, account_password=self.account_data.account_password)

                logger.info(f"Account: {self.account_data.email} | Logging in | Attempt: {attempt + 1}/{max_attempts}..")
                proxy = await self._prepare_account_proxy(db_account_value)
                api = _3dosAPI(proxy=proxy)

                if not relogin:
                    access_token = await self._login_account(api=api)
                else:
                    access_token = await self._login_account(
                        api=api,
                        email=db_account_value.email,
                        password=db_account_value.account_password
                    )

                api.access_token = access_token

                profile_info = await api.profile_info()
                referral_code = profile_info["referral_code"]
                sui_address = profile_info["sui_address"]
                api_secret = profile_info["api_secret"]

                await self._save_account(
                    db_account_value=db_account_value,
                    proxy=proxy,
                    access_token=access_token,
                    sui_address=sui_address,
                    referral_code=referral_code,
                    api_secret=api_secret,
                )

                logger.success(f"Account: {self.account_data.email} | Logged in | Session saved to database")
                return operation_success(email=self.account_data.email, account_password=self.account_data.account_password)

            except APIError as error:
                is_last_attempt = attempt == max_attempts - 1
                if is_last_attempt:
                    logger.error(f"Account: {self.account_data.email} | Max attempts reached, unable to login")
                    return operation_success(email=self.account_data.email, account_password=self.account_data.account_password)

                if error.error_type == APIErrorType.INVALID_CAPTCHA:
                    logger.error(f"Account: {self.account_data.email} | Captcha answer incorrect | Retrying in {config.attempts_and_delay_settings.error_delay} seconds")
                    await asyncio.sleep(config.attempts_and_delay_settings.error_delay)
                    continue

                logger.error(f"Account: {self.account_data.email} | Error occurred during login (APIError): {error} | Skipped permanently")
                return operation_failed(email=self.account_data.email, account_password=self.account_data.account_password)

            except Exception as error:
                is_last_attempt = attempt == max_attempts - 1
                if is_last_attempt:
                    logger.error(f"Account: {self.account_data.email} | Max attempts reached, unable to login")
                    return operation_success(email=self.account_data.email, account_password=self.account_data.account_password)

                logger.error(f"Account: {self.account_data.email} | Error occurred during login (Generic Exception): {error}")
                await self._update_account_proxy(db_account_value, attempt)


    async def process_export_stats(self):
        max_attempts = config.attempts_and_delay_settings.max_stats_attempts

        for attempt in range(max_attempts):
            db_account_value, api = None, None

            try:
                db_account_value = await Accounts.get_account(email=self.account_data.email)
                if not db_account_value or not db_account_value.access_token:
                    await self.handle_invalid_account(self.account_data.email, self.account_data.account_password, "unlogged")
                    return

                logger.info(f"Account: {self.account_data.email} | Exporting stats | Attempt: {attempt + 1}/{max_attempts}..")
                proxy = await self._prepare_account_proxy(db_account_value)
                api = _3dosAPI(access_token=db_account_value.access_token, proxy=proxy)

                profile_info = await api.profile_info()
                profile_info["email_password"] = db_account_value.email_password
                profile_info["account_password"] = db_account_value.account_password

                logger.success(f"Account: {self.account_data.email} | Stats exported")
                return operation_success(
                    email=db_account_value.email,
                    email_password=db_account_value.email_password,
                    account_password=db_account_value.account_password,
                    data=profile_info,
                )

            except APIError as error:
                if error.error_type == APIErrorType.EMAIL_NOT_VERIFIED:
                    await self.handle_invalid_account(db_account_value.email, db_account_value.email_password, db_account_value.account_password, "unverified")
                    return

                logger.error(f"Account: {self.account_data.email} | Error occurred while exporting stats (APIError): {error} | Skipped permanently")

            except Exception as error:
                is_last_attempt = attempt == max_attempts - 1
                if is_last_attempt:
                    logger.error(f"Account: {self.account_data.email} | Max attempts reached, unable to export stats")
                    return operation_failed(db_account_value.email, db_account_value.email_password, db_account_value.account_password)

                error = validate_error(error)
                logger.error(f"Account: {self.account_data.email} | Error occurred while exporting stats (Generic Exception): {error}")
                await self._update_account_proxy(db_account_value, attempt)


    async def process_farm(self):
        max_attempts = config.attempts_and_delay_settings.max_farm_attempts

        for attempt in range(max_attempts):
            db_account_value, api = None, None

            try:
                db_account_value = await Accounts.get_account(email=self.account_data.email)
                if not db_account_value or not db_account_value.access_token:
                    await self.handle_invalid_account(self.account_data.email, self.account_data.account_password, "unlogged")
                    return

                proxy = await self._prepare_account_proxy(db_account_value)
                api = _3dosAPI(access_token=db_account_value.access_token, proxy=proxy)

                if db_account_value.sleep_until:
                    sleep_duration = await handle_sleep(db_account_value.sleep_until)
                    if sleep_duration is True:
                        return

                profile_info = await api.profile_info() if not db_account_value.api_secret else await api.profile_info_by_secret_key(api_secret=db_account_value.api_secret)
                loyalty_points = profile_info["loyalty_points"]
                current_tier = profile_info['current_tier']

                if not db_account_value.api_secret:
                    if profile_info["api_secret"] is not None:
                        await db_account_value.update_account(api_secret=profile_info["api_secret"])
                    else:
                        logger.info(f"Account: {self.account_data.email} | API secret not found, fetching from API..")
                        api_secret = await api.generate_api_key()
                        await db_account_value.update_account(api_secret=api_secret)
                        logger.success(f"Account: {self.account_data.email} | API secret fetched")

                if profile_info["daily_reward_claim"] is None:
                    points = await api.claim_daily_reward()
                else:
                    next_claim_str = profile_info["next_daily_reward_claim"]
                    next_claim_time = datetime.fromisoformat(next_claim_str.replace("Z", "+00:00"))
                    now_utc = datetime.now(timezone.utc)

                    if now_utc >= next_claim_time:
                        points = await api.claim_daily_reward()
                    else:
                        points = None

                if points is not None:
                    logger.success(f"Account: {self.account_data.email} | Daily reward claimed | Received Points: {points}")
                    loyalty_points += points

                logger.success(f"Account: {self.account_data.email} | Loyalty points: {loyalty_points} | Current Tier: {current_tier}")
                await db_account_value.set_sleep_until(get_sleep_until(minutes=config.application_settings.farm_delay))

            except APIError as error:
                if error.error_type == APIErrorType.EMAIL_NOT_VERIFIED:
                    await self.handle_invalid_account(self.account_data.email, self.account_data.password, self.account_data.account_password, "unverified")
                    return

                elif error.error_type == APIErrorType.UNAUTHENTICATED:
                    logger.warning(f"Account: {self.account_data.email} | Unauthenticated, logging in again..")
                    operation_result = await self.process_login(relogin=True)
                    if operation_result and operation_result["success"]:
                        logger.success(f"Account: {self.account_data.email} | Re-login success, retrying farm")
                        continue
                    else:
                        logger.error(f"Account: {self.account_data.email} | Re-login failed, skipping until next cycle")
                        return

                await db_account_value.set_sleep_until(get_sleep_until(minutes=config.application_settings.farm_delay))
                logger.error(f"Account: {self.account_data.email} | Error occurred while farm (APIError): {error} | Skipped until next cycle")

            except Exception as error:
                is_last_attempt = attempt == max_attempts - 1
                if is_last_attempt:
                    await db_account_value.set_sleep_until(get_sleep_until(minutes=config.application_settings.farm_delay))
                    logger.error(f"Account: {self.account_data.email} | Max attempts reached, unable to farm | Skipped until next cycle")
                    return
                else:
                    error = validate_error(error)
                    logger.error(f"Account: {self.account_data.email} | Error occurred while farm (Generic Exception): {error}")
                    await self._update_account_proxy(db_account_value, attempt)

            finally:
                if api:
                    await api.close_session()
