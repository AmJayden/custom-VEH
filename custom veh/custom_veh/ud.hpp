#pragma once
#include <optional>
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <string_view>
#include <fstream>

#include <Windows.h>
#include <winternl.h>

#if defined(_MSC_VER)
#define UD_FORCEINLINE __forceinline
#pragma warning( push )
#pragma warning( disable : 4244 4083 )
#else
#define UD_FORCEINLINE __attribute__( ( always_inline ) )
#endif

#define ud_encode_c( str ) ud::rot::decode( ud::rot::rot_t<str>{ } ).data
#define ud_encode( str ) std::string_view{ ud_encode_c( str ) }

#define ud_xorstr_c( str ) ud::xorstr::decrypt( ud::xorstr::xorstr_t< str, __COUNTER__ + 1 ^ 0x90 >{ } ).data
#define ud_xorstr( str ) std::string_view{ ud_xorstr_c( str ) }

#define ud_stack_str( str ) ud::details::comp_string_t{ str }.data

// settings defined below, preprocessed due to compiler errors present even with "if constexpr"
#define UD_USE_SEH false

namespace ud
{
	namespace details
	{
		struct PEB_LDR_DATA
		{
			unsigned long dummy_0;
			unsigned long dummy_1;
			const char* dummy_2;
			LIST_ENTRY* in_load_order_module_list;
		};

		struct LDR_DATA_TABLE_ENTRY32
		{
			LIST_ENTRY InLoadOrderLinks;

			std::uint8_t pad[ 16 ];
			std::uintptr_t dll_base;
			std::uintptr_t entry_point;
			std::size_t size_of_image;

			UNICODE_STRING full_name;
			UNICODE_STRING base_name;
		};

		struct LDR_DATA_TABLE_ENTRY64
		{
			LIST_ENTRY InLoadOrderLinks;
			LIST_ENTRY dummy_0;
			LIST_ENTRY dummy_1;

			std::uintptr_t dll_base;
			std::uintptr_t entry_point;
			union {
				unsigned long size_of_image;
				const char* _dummy;
			};

			UNICODE_STRING full_name;
			UNICODE_STRING base_name;
		};

#ifdef _M_X64
		using LDR_DATA_TABLE_ENTRY = LDR_DATA_TABLE_ENTRY64;
#else
		using LDR_DATA_TABLE_ENTRY = LDR_DATA_TABLE_ENTRY32;
#endif

		template < std::size_t sz >
		struct comp_string_t
		{
			std::size_t size = sz;
			char data[ sz ]{ };

			comp_string_t( ) = default;
			consteval comp_string_t( const char( &str )[ sz ] )
			{
				std::copy_n( str, sz, data );
			}
		};

		inline constexpr std::uint64_t multiplier = 0x5bd1e995;
		inline consteval std::uint64_t get_seed( )
		{
			constexpr auto time_str = __TIME__;
			constexpr auto time_len = sizeof( __TIME__ ) - 1;

			constexpr auto time_int = [ ] ( const char* const str, const std::size_t len )
			{
				auto res = 0ull;
				for ( auto i = 0u; i < len; ++i )
					if ( str[ i ] >= '0' && str[ i ] <= '9' )
						res = res * 10 + str[ i ] - '0';

				return res;
			}( time_str, time_len );

			return time_int;
		}

		template < auto v >
		struct constant_t
		{
			enum : decltype( v )
			{
				value = v
			};
		};

		template < auto v >
		inline constexpr auto constant_v = constant_t< v >::value;

#undef max
#undef min

		template < std::uint32_t seq >
		consteval std::uint64_t recursive_random( )
		{
			constexpr auto seed = get_seed( );
			constexpr auto mask = std::numeric_limits< std::uint64_t >::max( );

			constexpr auto x = ( ( seq * multiplier ) + seed ) & mask;
			constexpr auto x_prime = ( x >> 0x10 ) | ( x << 0x10 );

			return constant_v< x_prime >;
		}
	}

	inline std::optional< std::string > get_dialogue_path( const std::string_view type = "", const HWND wnd = nullptr )
	{
		OPENFILENAMEA ofn;
		char path[ MAX_PATH ]{ };

		ZeroMemory( &ofn, sizeof( ofn ) );
		ofn.lStructSize = sizeof( ofn );
		ofn.hwndOwner = wnd;
		ofn.lpstrFilter = type.empty( ) ? "All Files (*.*)\0*.*\0" : type.data( );
		ofn.lpstrFile = path;
		ofn.nMaxFile = MAX_PATH;
		ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

		if ( GetOpenFileNameA( &ofn ) )
			return { path };

		return std::nullopt;
	}

	inline std::optional< std::string > read_file( const std::string_view path )
	{
		std::ifstream file( path.data( ) );
		if ( !file.is_open( ) )
			return std::nullopt;

		std::string content;
		file.seekg( 0, std::ios::end );
		content.reserve( file.tellg( ) );
		file.seekg( 0, std::ios::beg );

		content.assign( std::istreambuf_iterator< char >( file ), std::istreambuf_iterator< char >( ) );
		return content;
	}

	inline std::optional< std::pair< std::string, std::string > > read_dialogue( const std::string_view type = "", const HWND wnd = nullptr )
	{
		const auto path = get_dialogue_path( type, wnd );
		if ( !path )
			return std::nullopt;

		const auto content = read_file( *path );
		if ( !content )
			return std::nullopt;

		return std::make_pair( *path, *content );
	}

	template< typename ty >
	std::optional< ty > get_window_prop( const HWND wnd, const char* const prop )
	{
		const auto allocation = GetPropA( wnd, prop );

		return allocation ? std::make_optional( *reinterpret_cast< ty* >( allocation ) ) : std::nullopt;
	}

	template < typename ty >
	void set_window_prop( const HWND wnd, const char* const prop, const ty value )
	{
		std::unique_ptr< void, decltype( &LocalFree ) > x = { LocalAlloc( LMEM_ZEROINIT, sizeof( ty ) ), &LocalFree };
		if ( !x )
			return;

		*reinterpret_cast< ty* >( x.get( ) ) = value;
		SetPropA( wnd, prop, x.get( ) );
	}

	template < typename ty = std::uintptr_t >
	std::optional< ty > find_pattern_primitive( const std::uintptr_t start, const std::uintptr_t end, const std::string_view pattern )
	{
		std::vector< std::pair< bool, std::uint8_t > > bytes;

		for ( auto it = pattern.begin( ); it != pattern.end( ); ++it )
		{
			if ( *it == ' ' )
				continue;

			else if ( *it == '?' )
			{
				if ( it + 1 < pattern.end( ) && *( it + 1 ) == '?' )
				{
					bytes.push_back( { true, 0x00 } );
					++it;
				}

				else
					bytes.push_back( { false, 0x00 } );
			}

			else
			{
				if ( it + 1 == pattern.end( ) )
					break;

				const auto get_byte = [ ] ( const std::string x ) -> std::uint8_t
				{
					return static_cast< std::uint8_t >( std::stoul( x, nullptr, 16 ) );
				};

				bytes.emplace_back( false, get_byte( std::string( it - 1, ( ++it ) + 1 ) ) );
			}
		}

		for ( auto i = reinterpret_cast< const std::uint8_t* >( start ); i < reinterpret_cast< const std::uint8_t* >( end ); )
		{
			auto found = true;
			for ( const auto [is_wildcard, byte] : bytes )
			{
				++i;

				if ( is_wildcard )
					continue;

				if ( *i != byte )
				{
					found = false;
					break;
				}
			}

			if ( found )
				return ty( i - bytes.size( ) + 1 );
		}

		return std::nullopt;
	}

	struct segment_t
	{
		std::string_view name = "";
		std::uintptr_t start{ }, end{ };
		std::size_t size{ };

		template < typename ty = std::uintptr_t >
		std::optional< ty > find_pattern( const std::string_view pattern ) const
		{
			return find_pattern_primitive< ty >( start, end, pattern );
		}

		segment_t( const std::string_view segment_name )
		{
			init( GetModuleHandle( nullptr ), segment_name );
		}

		segment_t( const void* const module, const std::string_view segment_name )
		{
			init( module, segment_name );
		}

		segment_t( const void* const handle, const IMAGE_SECTION_HEADER* section )
		{
			init( handle, section );
		}

	private:
		void init( const void* const handle, const IMAGE_SECTION_HEADER* section )
		{
			name = std::string_view( reinterpret_cast< const char* >( section->Name ), 8 );
			start = reinterpret_cast< std::uintptr_t >( handle ) + section->VirtualAddress;
			end = start + section->Misc.VirtualSize;
			size = section->Misc.VirtualSize;
		}

		void init( const void* const handle, const std::string_view segment_name )
		{
			const auto dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( handle );
			const auto nt = reinterpret_cast< const IMAGE_NT_HEADERS* >( reinterpret_cast< const std::uint8_t* >( handle ) + dos->e_lfanew );

			const auto section = reinterpret_cast< const IMAGE_SECTION_HEADER* >( reinterpret_cast< const std::uint8_t* >( &nt->OptionalHeader ) + nt->FileHeader.SizeOfOptionalHeader );

			for ( auto i = 0u; i < nt->FileHeader.NumberOfSections; ++i )
			{
				if ( std::string_view( reinterpret_cast< const char* >( section[ i ].Name ), 8 ).find( segment_name ) != std::string_view::npos )
				{
					start = reinterpret_cast< std::uintptr_t >( handle ) + section[ i ].VirtualAddress;
					end = start + section[ i ].Misc.VirtualSize;
					size = section[ i ].Misc.VirtualSize;
					name = segment_name;
					return;
				}
			}

			throw std::runtime_error( "Segment not found" );
		}
	};

#pragma code_seg( push, ".text" )
	template < auto... bytes>
	struct shellcode_t
	{
		static constexpr std::size_t size = sizeof...( bytes );
		__declspec( allocate( ".text" ) ) static constexpr std::uint8_t data[ ]{ bytes... };
	};
#pragma code_seg( pop )

	template < typename ty, auto... bytes >
	constexpr ty make_shellcode( )
	{
		return reinterpret_cast< const ty >( &shellcode_t< bytes... >::data );
	}

	template < std::uint8_t... bytes >
	UD_FORCEINLINE constexpr void emit( )
	{
#if defined( __clang__ ) || defined( __GNUC__ )
		constexpr std::uint8_t data[ ]{ bytes... };

		for ( auto i = 0u; i < sizeof...( bytes ); ++i )
			__asm volatile( ".byte %c0\t\n" :: "i" ( data[ i ] ) );
#endif
	}

	template < std::size_t size, std::uint32_t seed = __COUNTER__ + 0x69, std::size_t count = 0 >
	UD_FORCEINLINE constexpr void emit_random( )
	{
		if constexpr ( count < size )
		{
			constexpr auto random = details::recursive_random< seed >( );
			emit< static_cast< std::uint8_t >( random ) >( );
			emit_random< size, static_cast< std::uint32_t >( random )* seed, count + 1 >( );
		}
	}

	inline bool is_valid_page( const void* const data, const std::uint32_t flags = PAGE_READWRITE )
	{
		MEMORY_BASIC_INFORMATION mbi{ };

		if ( !VirtualQuery( data, &mbi, sizeof( mbi ) ) )
			return false;

		return mbi.Protect & flags;
	}

	struct export_t
	{
		std::string_view name = "";
		std::uint16_t ordinal{ };
		std::uintptr_t address{ };
	};

	struct module_t
	{
		std::string name;
		std::uintptr_t start, end;
		std::size_t size;

		std::vector< export_t > get_exports( ) const
		{
			const auto dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( start );
			const auto nt = reinterpret_cast< const IMAGE_NT_HEADERS* >( start + dos->e_lfanew );

			const auto directory_header = nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
			if ( !directory_header.VirtualAddress )
				return { };

			const auto export_dir = reinterpret_cast< const IMAGE_EXPORT_DIRECTORY* >( start + directory_header.VirtualAddress );
			const auto name_table = reinterpret_cast< const std::uint32_t* >( start + export_dir->AddressOfNames );
			const auto ord_table = reinterpret_cast< const std::uint16_t* >( start + export_dir->AddressOfNameOrdinals );
			const auto addr_table = reinterpret_cast< const std::uint32_t* >( start + export_dir->AddressOfFunctions );

			std::vector< export_t > exports( export_dir->NumberOfNames );

			for ( auto i = 0u; i < export_dir->NumberOfNames; ++i )
			{
				const auto name = reinterpret_cast< const char* >( start + name_table[ i ] );
				const auto ord = ord_table[ i ];
				const auto addr = start + addr_table[ ord ];

				exports[ i ] = { name, ord, addr };
			}

			return exports;
		}

		std::vector< segment_t > get_segments( ) const
		{
			const auto dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( start );
			const auto nt = reinterpret_cast< const IMAGE_NT_HEADERS* >( start + dos->e_lfanew );

			const auto section = reinterpret_cast< const IMAGE_SECTION_HEADER* >( reinterpret_cast< const std::uint8_t* >( &nt->OptionalHeader ) + nt->FileHeader.SizeOfOptionalHeader );

			std::vector< segment_t > segments;
			segments.reserve( nt->FileHeader.NumberOfSections );

			for ( auto i = 0u; i < nt->FileHeader.NumberOfSections; ++i )
			{
				const segment_t seg( dos, &section[ i ] );
				segments.push_back( seg );
			}

			return segments;
		}

		std::vector< export_t > get_imports( ) const
		{
			const auto dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( start );
			const auto nt = reinterpret_cast< const IMAGE_NT_HEADERS* >( start + dos->e_lfanew );

			const auto directory_header = &nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
			if ( !directory_header->VirtualAddress )
				return { };

			const auto import_dir = reinterpret_cast< const IMAGE_IMPORT_DESCRIPTOR* >( start + directory_header->VirtualAddress );
			std::vector< export_t > imports;

			for ( auto i = 0u;; ++i )
			{
				if ( !import_dir[ i ].OriginalFirstThunk )
					break;

				const auto directory = &import_dir[ i ];

				const auto name_table = reinterpret_cast< const std::uint32_t* >( start + directory->OriginalFirstThunk );
				const auto addr_table = reinterpret_cast< const std::uint32_t* >( start + directory->FirstThunk );

				for ( auto j = 0u;; ++j )
				{
					if ( !addr_table[ j ] )
						break;

					if ( !name_table[ j ] )
						continue;

					std::string_view name;

					constexpr auto name_alignment = 2;

					const auto addr = &addr_table[ j ];
					const auto name_ptr = reinterpret_cast< const char* >( start + name_table[ j ] ) + name_alignment;

#if UD_USE_SEH
						// using SEH here is not a very good solution
						// however, it's faster than querying that page protection to see if it's readable
						__try
						{
							name = name_ptr;
						}
						__except ( EXCEPTION_EXECUTE_HANDLER )
						{
							name = "";
						}
#else
						// runtime overhead of ~3us compared to SEH on single calls
						// on bulk calls it can go up to ~300-500us 
						name = is_valid_page( name_ptr, PAGE_READONLY ) ? name_ptr : "";
#endif

					// emplace_back doesn't allow for implicit conversion, so we have to do it manually
					imports.push_back( { name, static_cast< std::uint16_t >( j ), reinterpret_cast< std::uintptr_t >( addr ) } );
				}
			}

			return imports;
		}

		template < typename ty = std::uintptr_t >
		ty get_address( const std::string_view name ) const
		{
			for ( const auto& export_ : get_exports( ) )
			{
				if ( export_.name.find( name ) != std::string_view::npos )
					return ty( export_.address );
			}

			return 0;
		}

		template < typename ty = std::uintptr_t >
		std::optional< ty > find_pattern( const std::string_view pattern ) const
		{
			return find_pattern_primitive< ty >( start, end, pattern );
		}

		module_t( )
		{
			init( GetModuleHandle( nullptr ) );
		}

		module_t( void* const handle )
		{
			init( handle );
		}

		module_t( const std::string_view module_name )
		{
			init( GetModuleHandleA( module_name.data( ) ) );
		}

	private:
		void* module;

		void init( void* const handle )
		{
			module = handle;

			const auto dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( handle );
			const auto nt = reinterpret_cast< const IMAGE_NT_HEADERS* >( reinterpret_cast< const std::uint8_t* >( handle ) + dos->e_lfanew );

			start = reinterpret_cast< std::uintptr_t >( handle );
			end = start + nt->OptionalHeader.SizeOfImage;
			size = nt->OptionalHeader.SizeOfImage;

			char buffer[ MAX_PATH ];
			const auto sz = GetModuleFileNameA( static_cast< HMODULE >( handle ), buffer, MAX_PATH );

			name = sz ? std::string{ buffer, sz } : std::string{ };
		}
	};

	inline std::vector< module_t > get_modules( )
	{
		std::vector< module_t > result;

#ifdef _M_X64
		const auto peb = reinterpret_cast< const PEB* >( __readgsqword( 0x60 ) );
#else
		const auto peb = reinterpret_cast< const PEB* >( __readfsdword( 0x30 ) );
#endif

		const auto modules = reinterpret_cast< const LIST_ENTRY* >( peb->Ldr->InMemoryOrderModuleList.Flink );
		for ( auto i = modules->Flink; i != modules; i = i->Flink )
		{
			const auto entry = reinterpret_cast< const LDR_DATA_TABLE_ENTRY* >( i );

			if ( entry->Reserved2[ 0 ] || entry->DllBase )
				result.emplace_back( entry->Reserved2[ 0 ] ? entry->Reserved2[ 0 ] : entry->DllBase );
		}

		return result;
	}

	inline std::optional< module_t > get_module_at_address( const std::uintptr_t address )
	{
		for ( const auto& module : get_modules( ) )
		{
			if ( module.start <= address && address < module.end )
				return module;
		}

		return std::nullopt;
	}

	inline std::optional< export_t > get_export( const std::uintptr_t address )
	{
		for ( const auto& module : get_modules( ) )
		{
			if ( module.start <= address && address < module.end )
			{
				const auto exports = module.get_exports( );
				for ( const auto& export_ : exports )
				{
					if ( export_.address == address )
						return export_;
				}
			}
		}

		return std::nullopt;
	}

	namespace rot
	{
		template < details::comp_string_t str >
		struct rot_t
		{
			char rotted[ str.size ];

			consteval const char* encoded( ) const
			{
				return rotted;
			}

			consteval rot_t( )
			{
				for ( auto i = 0u; i < str.size; ++i )
				{
					const auto c = str.data[ i ];
					const auto set = c >= 'A' && c <= 'Z' ? 'A' : c >= 'a' && c <= 'z' ? 'a' : c;

					if ( set == 'a' || set == 'A' )
						rotted[ i ] = ( c - set - 13 + 26 ) % 26 + set;

					else
						rotted[ i ] = c;
				}
			}
		};

		template < details::comp_string_t str >
		UD_FORCEINLINE details::comp_string_t< str.size > decode( rot_t< str > encoded )
		{
			details::comp_string_t< str.size > result{ };

			for ( auto i = 0u; i < str.size; ++i )
			{
				const auto c = encoded.rotted[ i ];
				const auto set = c >= 'A' && c <= 'Z' ? 'A' : c >= 'a' && c <= 'z' ? 'a' : c;

				if ( set == 'a' || set == 'A' )
					result.data[ i ] = ( c - set - 13 + 26 ) % 26 + set;

				else
					result.data[ i ] = c;
			}

			return result;
		}
	}

	namespace fnv
	{
		inline constexpr std::uint32_t fnv_1a( const char* const str, const std::size_t size )
		{
			constexpr auto prime = 16777619u;

			std::uint32_t hash = 2166136261;

			for ( auto i = 0u; i < size; ++i )
			{
				hash ^= str[ i ];
				hash *= prime;
			}

			return hash;
		}

		inline constexpr std::uint32_t fnv_1a( const std::string_view str )
		{
			return fnv_1a( str.data( ), str.size( ) );
		}

		template < details::comp_string_t str >
		consteval std::uint32_t fnv_1a( )
		{
			return fnv_1a( str.data, str.size );
		}
	}

	namespace xorstr
	{
		template < details::comp_string_t str, std::uint32_t key_multiplier >
		struct xorstr_t
		{
			char xored[ str.size ];

			consteval std::uint64_t xor_key( ) const
			{
				return details::recursive_random< key_multiplier >( );
			}

			consteval xorstr_t( )
			{
				for ( auto i = 0u; i < str.size; ++i )
					xored[ i ] = str.data[ i ] ^ xor_key( );
			}
		};

		template < details::comp_string_t str, std::uint32_t key_multiplier >
		UD_FORCEINLINE details::comp_string_t< str.size > decrypt( xorstr_t< str, key_multiplier > enc )
		{
			details::comp_string_t< str.size > result{ };

			for ( auto i = 0u; i < str.size; ++i )
			{
				const auto c = enc.xored[ i ];

				result.data[ i ] = c ^ enc.xor_key( );
			}

			return result;
		}
	}
}

template < std::size_t size >
UD_FORCEINLINE std::ostream& operator<<( std::ostream& os, const ud::details::comp_string_t< size >& str )
{
	return os << std::string_view{ str.data, str.size };
}

#if defined( _MSC_VER )
#pragma warning( pop )
#endif