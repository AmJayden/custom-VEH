#include "custom_veh.hpp"
#include "ud.hpp"

#include <MinHook.h>
#include <stdexcept>

#define VEH_SHOULD_THROW true

#if VEH_SHOULD_THROW
#define VEH_EXCEPT( msg ) throw std::runtime_error( msg )
#else
#define VEH_EXCEPT( msg ) return false
#endif

bool custom_veh::add_vectored_handler( vectored_handler_t handler, bool first )
{
	if ( std::find( g_vectored_handlers.begin( ), g_vectored_handlers.end( ), handler ) == g_vectored_handlers.end( ) )
		return ( first ? g_vectored_handlers.push_front( handler ) : g_vectored_handlers.push_back( handler ) ), true;

	VEH_EXCEPT( ud_xorstr_c( "handler already present" ) );
}

bool custom_veh::remove_vectored_handler( vectored_handler_t handler )
{
	const auto it = std::find( g_vectored_handlers.begin( ), g_vectored_handlers.end( ), handler );
	
	if ( it != g_vectored_handlers.end( ) )
		return g_vectored_handlers.erase( it ), true;
	
	VEH_EXCEPT( ud_xorstr_c( "handler not present" ) );
}

#pragma optimize( "", off )
static bool( __fastcall* call_trampoline )( EXCEPTION_RECORD*, CONTEXT* );
static bool __fastcall call_vectored_handlers( EXCEPTION_RECORD* record, CONTEXT* ctx )
{
	for ( auto callback : custom_veh::g_vectored_handlers )
	{
		EXCEPTION_POINTERS info{ record, ctx };
		const auto status = callback( &info );
			
		if ( status != EXCEPTION_CONTINUE_SEARCH )
			return status == EXCEPTION_CONTINUE_EXECUTION;
	}

	return call_trampoline( record, ctx );
}

bool custom_veh::start_veh( )
{
	const ud::module_t ntdll{ ud_xorstr( "ntdll.dll" ) };
	
#if defined( _M_IX86 )
	const auto rtl_call_handlers = reinterpret_cast< void* >( *ntdll.find_pattern( ud_xorstr( "FC FE FF FF 8B FF 55 8B EC" ) ) + 4 );
#else
	const auto rtl_call_handlers = (ntdll.find_pattern< void* >( ud_xorstr( "40 55 56 57 41 54 41 55 41 56 41 57 48 81 EC D0" ) );
#endif

	if ( !rtl_call_handlers )
		VEH_EXCEPT( ud_xorstr_c( "rtl_call_handlers not found" ) );

	if ( MH_Initialize( ) )
		VEH_EXCEPT( ud_xorstr_c( "MH_Initialize failed" ) );

	if ( MH_CreateHook( rtl_call_handlers, &call_vectored_handlers, reinterpret_cast< void** >( &call_trampoline ) ) )
		VEH_EXCEPT( ud_xorstr_c( "MH_CreateHook failed" ) );

	if ( MH_EnableHook( rtl_call_handlers ) )
		VEH_EXCEPT( ud_xorstr_c( "MH_EnableHook failed" ) );

	return true;
}

#pragma optimize( "", on )
