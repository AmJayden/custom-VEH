#pragma once
#include <deque>
#include <cstdint>

#include <Windows.h>

namespace custom_veh
{
	using vectored_handler_t = std::uint32_t( * )( EXCEPTION_POINTERS* );
	
	static std::deque< vectored_handler_t > g_vectored_handlers;
	
	bool add_vectored_handler( vectored_handler_t handler, bool first = true );
	bool remove_vectored_handler( vectored_handler_t handler );

	bool start_veh( );
}
