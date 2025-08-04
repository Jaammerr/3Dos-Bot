import asyncio
import json
import random
import names

from datetime import datetime, timezone
from typing import Literal

from curl_cffi.requests import AsyncSession, Response
from utils.processing.handlers import require_access_token
from core.exceptions.base import APIError, SessionRateLimited, ServerError, ProxyForbidden
from loader import config




class APIClient:
    API_URL = "https://api.dashboard.3dos.io/api"

    def __init__(self, proxy: str = None):
        self.proxy = proxy
        self.session = self._create_session()
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"

    def _create_session(self) -> AsyncSession:
        session = AsyncSession(impersonate="chrome136", verify=False)
        session.timeout = 30

        if self.proxy:
            session.proxies = {
                "http": self.proxy,
                "https": self.proxy,
            }

        return session


    async def clear_request(self, url: str) -> Response:
        session = self._create_session()
        return await session.get(url, allow_redirects=True, verify=False)

    @staticmethod
    async def _verify_response(response_data: dict | list):
        if isinstance(response_data, dict):
            if "status" in str(response_data):
                if response_data.get("status") == "Error":
                    raise APIError(
                        f"API returned an error: {response_data}", response_data
                    )

            elif response_data.get("error"):
                raise APIError(
                    f"API returned an error: {response_data['error']}", response_data
                )


    async def close_session(self) -> None:
        try:
            await self.session.close()
        except:
            pass

    async def send_request(
        self,
        request_type: Literal["POST", "GET", "OPTIONS"] = "POST",
        method: str = None,
        json_data: dict = None,
        params: dict = None,
        url: str = None,
        headers: dict = None,
        cookies: dict = None,
        verify: bool = True,
        max_retries: int = 2,
        retry_delay: float = 3.0,
    ):
        if not url:
            url = f"{self.API_URL}{method}"

        for attempt in range(max_retries):
            try:
                if request_type == "POST":
                    response = await self.session.post(
                        url,
                        json=json_data,
                        params=params,
                        headers=headers if headers else self.session.headers,
                        cookies=cookies,
                    )
                elif request_type == "OPTIONS":
                    response = await self.session.options(
                        url,
                        headers=headers if headers else self.session.headers,
                        cookies=cookies,
                    )
                else:
                    response = await self.session.get(
                        url,
                        params=params,
                        headers=headers if headers else self.session.headers,
                        cookies=cookies,
                    )

                if verify:
                    if response.status_code == 403 and "403 Forbidden" in response.text:
                        raise ProxyForbidden(f"Proxy forbidden - {response.status_code}")

                    elif response.status_code == 429:
                        raise SessionRateLimited("Session is rate limited")

                    if response.status_code in (500, 502, 503, 504):
                        print(response.text, response.headers, response.status_code)
                        raise ServerError(f"Server error - {response.status_code}")

                    try:
                        response_json = response.json()
                        await self._verify_response(response_json)
                        return response_json
                    except json.JSONDecodeError:
                        raise ServerError(f"Failed to decode response, most likely server error")

                return response.text

            except ServerError as error:
                if attempt == max_retries - 1:
                    raise error
                await asyncio.sleep(retry_delay)

            except (APIError, SessionRateLimited, ProxyForbidden):
                raise

            except Exception as error:
                if attempt == max_retries - 1:
                    raise ServerError(
                        f"Failed to send request after {max_retries} attempts: {error}"
                    )
                await asyncio.sleep(retry_delay)

        raise ServerError(f"Failed to send request after {max_retries} attempts")


class _3dosAPI(APIClient):
    def __init__(self, access_token: str = None, proxy: str = None):
        super().__init__(proxy)
        self.access_token = access_token

    async def register(self, email: str, password: str, captcha_token: str, country_id: str = "233", referred_by: str = None) -> dict:
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9,ru;q=0.8',
            'content-type': 'application/json',
            'origin': 'https://dashboard.3dos.io',
            'referer': 'https://dashboard.3dos.io/',
            'user-agent': self.user_agent,
        }

        json_data = {
            'email': email,
            'password': password,
            'acceptTerms': True,
            'country_id': country_id,
            'referred_by': referred_by,
            'captcha_token': captcha_token,
        }

        response = await self.send_request(
            request_type="POST",
            method="/auth/register",
            json_data=json_data,
            headers=headers,
        )

        if not response["message"]:
            raise APIError("Most likely registration is closed by project, no message in response", response)

        return response["data"]


    async def login(self, email: str, password: str, captcha_token: str) -> str:
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9,ru;q=0.8',
            'content-type': 'application/json',
            'origin': 'https://dashboard.3dos.io',
            'referer': 'https://dashboard.3dos.io/',
            'user-agent': self.user_agent,
        }

        json_data = {
            'email': email,
            'password': password,
            'captcha_token': captcha_token,
        }

        response = await self.send_request(
            request_type="POST",
            method="/auth/login",
            json_data=json_data,
            headers=headers,
        )

        return response["data"]["access_token"]

    async def resend_verify_email(self) -> dict:
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9,ru;q=0.8',
            'authorization': f'Bearer {self.access_token}',
            'origin': 'https://dashboard.3dos.io',
            'referer': 'https://dashboard.3dos.io/',
            'user-agent': self.user_agent,
        }

        return await self.send_request(
            request_type="GET",
            method="/email/resend",
            headers=headers,
        )

    @require_access_token
    async def profile_info(self) -> dict:
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9,ru;q=0.8',
            'authorization': f'Bearer {self.access_token}',
            'origin': 'https://dashboard.3dos.io',
            'referer': 'https://dashboard.3dos.io/',
            'user-agent': self.user_agent,
        }

        json_data = {}
        response = await self.send_request(
            request_type="POST",
            method="/profile/me",
            json_data=json_data,
            headers=headers,
        )

        return response["data"]

    async def profile_info_by_secret_key(self, api_secret: str) -> dict:
        headers = {
            'accept': '*/*',
            'accept-language': 'uk-UA,uk;q=0.9,en-US;q=0.8,en;q=0.7',
            'origin': 'chrome-extension://lpindahibbkakkdjifonckbhopdoaooe',
            'user-agent': self.user_agent,
        }

        response = await self.send_request(
            request_type="POST",
            method=f"/profile/api/{api_secret}",
            headers=headers,
        )

        return response["data"]

    @require_access_token
    async def claim_daily_reward(self) -> int:
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9,ru;q=0.8',
            'authorization': f'Bearer {self.access_token}',
            'cache-control': 'no-cache',
            'content-type': 'application/json',
            'origin': 'https://dashboard.3dos.io',
            'referer': 'https://dashboard.3dos.io/',
            'user-agent': self.user_agent,
        }

        json_data = {
            'id': 'daily-reward-api',
        }

        response = await self.send_request(
            request_type="POST",
            method="/claim-reward",
            json_data=json_data,
            headers=headers,
        )
        return response["data"]["points"]

    @require_access_token
    async def generate_api_key(self) -> str:
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9,ru;q=0.8',
            'authorization': f'Bearer {self.access_token}',
            'cache-control': 'no-cache',
            'expires': '0',
            'origin': 'https://dashboard.3dos.io',
            'referer': 'https://dashboard.3dos.io/',
            'user-agent': self.user_agent,
        }

        json_data = {}
        response = await self.send_request(
            request_type="POST",
            method="/profile/generate-api-key",
            json_data=json_data,
            headers=headers,
        )

        return response["data"]["api_secret"]



