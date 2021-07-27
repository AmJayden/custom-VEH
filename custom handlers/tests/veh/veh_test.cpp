#include "../../veh/custom_veh.hpp"

#include <iostream>
#include <Windows.h>

using namespace custom_handlers::veh;

std::uint32_t custom_handler(PEXCEPTION_POINTERS info)
{
	std::cout << "I'm ran first!\n";

	return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI vanilla_handler(PEXCEPTION_POINTERS info)
{
	std::cout << "I'm ran second!\n";

	return EXCEPTION_CONTINUE_EXECUTION;
}

std::uint32_t custom_handler2(PEXCEPTION_POINTERS info)
{
	std::cout << std::hex << info->ExceptionRecord->ExceptionCode << " is handled!\n";

	return EXCEPTION_CONTINUE_EXECUTION;
}

std::uint32_t custom_handler3(PEXCEPTION_POINTERS info)
{
	if (info->ExceptionRecord->ExceptionCode == 0xDEAD)
	{
		std::cout << "dead exception is handled, raising error\n";
		info->ExceptionRecord->ExceptionCode = 0x90;
		return EXCEPTION_EXECUTE_HANDLER;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{
	try
	{
		start_custom_handler();

		add_vectored_handler(&custom_handler);
		AddVectoredExceptionHandler(TRUE, &vanilla_handler);

		RaiseException(0x90, 0, 0, nullptr);

		std::cout << "I'm executed!\n";

		add_vectored_handler(&custom_handler2);
		RaiseException(0xffaded, 0, 0, nullptr);

		std::cout << "I'm continued before vanilla handlers execution!\n";

		add_vectored_handler(&custom_handler3);
		RaiseException(0xDEAD, 0, 0, nullptr);

		std::cout << "I'm never executed :(\n";
	}
	catch (std::exception& e)
	{
		std::cout << e.what() << '\n';
		std::cin.get();
	}

	return 0;
}