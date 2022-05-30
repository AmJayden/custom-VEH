#include <iostream>
#include <Windows.h>

#include "custom_veh/custom_veh.hpp"

std::uint32_t custom_handler( PEXCEPTION_POINTERS info )
{
	std::cout << "I'm ran first!\n";

	return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI vanilla_handler( PEXCEPTION_POINTERS info )
{
	std::cout << "I'm ran second!\n";

	return EXCEPTION_CONTINUE_EXECUTION;
}

std::uint32_t custom_handler2( PEXCEPTION_POINTERS info )
{
	std::cout << std::hex << info->ExceptionRecord->ExceptionCode << " is handled!\n";

	return EXCEPTION_CONTINUE_EXECUTION;
}

void redir( )
{
	std::cout << "cf redir\n";

	RaiseException( 0x1337, 0, 0, nullptr );
}

int main( )
{
	custom_veh::start_veh( );
		
	custom_veh::add_vectored_handler( &custom_handler );
	AddVectoredExceptionHandler( TRUE, &vanilla_handler );
	RaiseException( 0x90, 0, 0, nullptr );

	std::cout << "I'm executed!\n";

	custom_veh::add_vectored_handler( &custom_handler2 );
	RaiseException( 0xffaded, 0, 0, nullptr );

	std::cout << "I'm continued before vanilla handlers execution!\n";

}