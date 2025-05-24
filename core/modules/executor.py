from core.bot.base import Bot
from loader import file_operations
from models import Account


class ModuleExecutor:
    def __init__(self, account: Account):
        self.account = account
        self.bot = Bot(account)

    async def _process_registration(self) -> None:
        operation_result = await self.bot.process_registration()
        if isinstance(operation_result, dict):
            await file_operations.export_result(operation_result, "register")

    async def _process_verify(self) -> None:
        operation_result = await self.bot.process_verification()
        if isinstance(operation_result, dict):
            await file_operations.export_result(operation_result, "verify")

    async def _process_login(self) -> None:
        operation_result = await self.bot.process_login()
        if isinstance(operation_result, dict):
            await file_operations.export_result(operation_result, "login")

    async def _process_export_stats(self) -> None:
        operation_result = await self.bot.process_export_stats()
        if isinstance(operation_result, dict):
            await file_operations.export_stats(operation_result)

    async def _process_farm(self) -> None:
        await self.bot.process_farm()
