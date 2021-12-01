

#include "CheckBigBool.h"
#include "AntiDebug.h"
#include "TestModeCheck.h"

int main()
{
	NoCrt::Console::printf(L"Test\n");



	

	ApiUnhook::UnhookApi(L"ntdll.dll", "NtClose"); //unhook NtClose

	
	NoCrt::Console::printf(L"IsDebugObject ->\t %x\n",AntiDebug::VMPEx::IsDebugObject());


	NoCrt::Console::printf(L"IsProcessDebugPort ->\t %x\n", AntiDebug::VMPEx::IsProcessDebugPort());


	NoCrt::Console::printf(L"Check test mode by   NtQuerySystemInformation ->\t %x\n", CheckTestMode::CodeIntCheck());
	
	NoCrt::Console::printf(L"Check test mode by  registry ->\t %x\n", CheckTestMode::Registry());

	NoCrt::Console::printf(L"Is HyperHide use for debugging ->\t %x\n", BlackListPool::IsHyperHideDebuggingProcess());


	NoCrt::Console::printf(L"BuildNumberIsHooked ->\t %x\n", AntiDebug::Util::BuildNumberIsHooked());



	NoCrt::Console::printf(L"Syscall number NtQueryInformationProcess ->\t %x\n", ApiUnhook::GetSyscallNumber(L"ntdll.dll", "NtQueryInformationProcess"));

	NoCrt::Console::cin();
	NoCrt::Console::cin();
}
