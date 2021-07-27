#include "custom_veh.hpp"

#include <MinHook.h>
#include <exception>

// throw exception on function failure
#define VEH_THROW_ON_FAIL 1

#if VEH_THROW_ON_FAIL
#define VEH_FAIL(msg) throw std::exception(msg)
#else
#define VEH_FAIL(x) return false
#endif

using namespace custom_handlers::veh;

static auto find_in_deque(vectored_handler_t ptr)
{
	// no need to reference function pointers
	for (auto i = 0u; i < g_vectored_handlers.size(); ++i)
		if (g_vectored_handlers[i] == ptr)
			return g_vectored_handlers.begin() + i;	

	return g_vectored_handlers.end();
}

bool custom_handlers::veh::add_vectored_handler(vectored_handler_t func, bool first)
{
	if (find_in_deque(func) == g_vectored_handlers.end())
		return (first ? g_vectored_handlers.push_front(func) : g_vectored_handlers.push_back(func)), true;

	VEH_FAIL("custom handler already exists!");
}

bool custom_handlers::veh::remove_vectored_handler(vectored_handler_t func)
{
	const auto& it = find_in_deque(func);
	if (it == g_vectored_handlers.end())
		VEH_FAIL("custom handler doesn't exist!");

	return (g_vectored_handlers.erase(it)), true;
}

static bool(__fastcall* g_handler_trampoline)(PEXCEPTION_RECORD, PCONTEXT, std::uint32_t);
static bool __fastcall call_handlers_hook(PEXCEPTION_RECORD record, PCONTEXT context, std::uint32_t base_idx)
{
	// prevent double executions of our handlers due to recursed calls
	// will not run on continue handlers (which don't matter in this case anyway)
	if (!base_idx)
	{
		// call our vectored exception handlers before RtlpCallVectoredHandlers calls the ones inside of LdrpVectorHandlerList
		for (auto f : g_vectored_handlers)
		{
			auto exception_info = EXCEPTION_POINTERS{ record, context };
			const auto result = f(&exception_info);

			// mimic real exception handler results
			// if not continuing search and isn't EXCEPTION_CONTINUE_EXECUTION (-1) return false
			// raising an exception, otherwise continue
			if (result != EXCEPTION_CONTINUE_SEARCH)
				return result == EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	// run through original
	return g_handler_trampoline(record, context, base_idx);
}

template <class T>
static inline std::uintptr_t calculate_rel(std::uintptr_t start, std::uint8_t sz, std::uint8_t off)
{
	return (start + sz + *reinterpret_cast<T*>(start + off));
}

bool custom_handlers::veh::start_custom_handler()
{
	// should never fail, but disallow warnings
	const auto ntdll = GetModuleHandleA("ntdll.dll");

	if (!ntdll)
		VEH_FAIL("unable to retrieve ntdll handle");

	const auto ki_dispatcher = reinterpret_cast<std::uintptr_t>(GetProcAddress(ntdll, "KiUserExceptionDispatcher"));

	if (!ki_dispatcher)
		VEH_FAIL("failed to get KiUserExceptionDispatcher");

#ifdef _M_IX86
	// SYSWOW64 ntdll
	const auto exception_dispatch = calculate_rel<std::int32_t>(ki_dispatcher + 0x21, 5, 1);
#else
	// System32 ntdll
	const auto exception_dispatch = calculate_rel<std::int32_t>(ki_dispatcher + 0x29, 5, 1);
#endif

	if (!exception_dispatch)
		VEH_FAIL("RtlDispatchException calculation yielded 0");

#ifdef _M_IX86
	// SYSWOW64 ntdll
	const auto call_vectored_handlers = calculate_rel<std::int32_t>(exception_dispatch + 0x6A, 5, 1);
#else
	// System32 ntdll
	const auto call_vectored_handlers = calculate_rel<std::int32_t>(exception_dispatch + 0x61, 5, 1);
#endif

	if (!call_vectored_handlers)
		VEH_FAIL("RtlpCallVectoredHandlers calculation yielded 0");

	if (MH_FAIL(MH_Initialize()))
		VEH_FAIL("failure to initialize minhook");

	if (MH_FAIL(MH_CreateHook(reinterpret_cast<void*>(call_vectored_handlers), &call_handlers_hook, reinterpret_cast<void**>(&g_handler_trampoline))))
		VEH_FAIL("unable to create handler hook");

	if (MH_FAIL(MH_EnableHook(reinterpret_cast<void*>(call_vectored_handlers))))
		VEH_FAIL("unable to enable create handler hook");

	return true;
}