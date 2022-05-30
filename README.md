# custom-VEH
custom vectored exception handlers for x86 and x64.

I'm sure this has been done before, and is likely well documented.


I didn't bother checking because my entire goal in this project was to see how easy it would be to pull this off.


I had fun doing this and it only took about an hour, so I'm sure there's likely to be issues with either my documentation or code, let me know in the issues if you see any.

# What is this?
This is a library allowing you to create custom vectored exception handlers that're faster than normal ones, and run before any vanilla handlers do.

These handlers are stored in a deque container as function pointers, outside of `LdrpVectorHandlerList`, being easier to manage and smaller while also being hard to manipulate outside of your process or dll.

# Usage
## Defining a handler
* You may define a custom exception handler with this format,
* from that point on the code of the handler works exactly like a normal one
```cpp
std::uint32_t custom_handler(PEXCEPTION_POINTERS info)
{
	std::cout << "I'm ran first!\n";

	return EXCEPTION_CONTINUE_SEARCH;
}
```

## Initializing the custom handler
```cpp
custom_veh::start_custom_handler();                   // call this exactly once in your program
custom_veh::add_vectored_handler(&custom_handler);    // call this to add a handler

custom_veh::remove_vectored_handler(&custom_handler);  // call this to remove a custom handler from execution
```

# How it works
this code hooks the function `RtlpCallVectoredHandlers` defined in ntdll.dll to call the user defined handlers
before the original VEHs are ran. Allowing it to run custom handlers not located in `LdrpVectorHandlerList` so vanilla handlers cannot be ran before custom ones.

# Reverse engineering and updating for future versions
Now the method behind actually retrieving `RtlpCallVectoredHandlers` is not very adaptable for future or older versions of ntdll with updates to `KiUserExceptionDispatcher` or `RtlDispatchException`.

The examples I'm going to show are performed on System32's ntdll, which is different from SYSWOW64's ntdll.
The System32 dll is meant for x64 programs, while SYSWOW64's dll is specific to x86 programs, however the process is the same for both.

Firstly, I went to `RtlAddVectoredExceptionHandler` to see how it worked, and saw that it was just a wrapper around `RtlpAddVectoredHandler`
![RtlAddVectoredExceptionHandler](https://i.imgur.com/afWGb3u.png)

## RtlpAddVectoredHandler
Then, going into `RtlpAddVectoredHandler`, I looked for where it referenced a handler list, which I'd quickly found.
![Vectored handler list](https://i.imgur.com/KWZ0SHq.png)

Next, I went to cross reference it to see where it was used and possibly find where the handlers are called.

And I easily found it in the xrefs.
![Vectored handler list xrefs](https://i.imgur.com/ODst0rQ.png)

Now in `RtlpCallVectoredHandlers` the first thing I wanted to identify were the arguments.

By referencing a1 and a2, I found out that they were just `ExceptionRecord` and `ExceptionContext` because they were being moved into what was obviously an `EXCEPTION_POINTERS` struct.

![ExceptionPointers struct](https://i.imgur.com/fA1qie8.png)

As for a3, I discovered that it was just a base index, which started at 1 on first calls for VectoredContinueHandlers, but starts at 0 for VectoredExceptionHandlers, so I named it `base_idx`.

And for handler calls, I saw that it was decoding a pointer to retrieve the handler pointer, then calling it with our ExceptionPointers.
![Handler calls](https://i.imgur.com/xtci1vk.png)

Finally, the result of the handler is compared with -1 (EXCEPTION_CONTINUE_EXECUTION), if true it removes the list entry and stops executing all other handlers and returns true, otherwise continues search. 
![Handler result](https://i.imgur.com/qXWLG8F.png)

## RtlDispatchException
After reversing `RtlpCallVectoredHandlers` I cross referenced to see how information is passed, and how I can retrieve it.

The only reference to it was `RtlDispatchException`.

I ignored a large part of this function since a big chunk had nothing to do with the information I needed,

but I did reverse the barebones to it.

Firstly, it's first 2 arguments are `ExceptionRecord` and `ExceptionContext` as they're passed to `RtlpCallVectoredHandlers`.

It calls `RtlpCallVectoredHandlers` passing 0 for the base, calling Exception handlers, if it returns false it prepares info for exception.

If the call returns true it runs through Continue handlers then returns true.

![Handler call](https://i.imgur.com/WJaMP65.png)

![continue_execution label](https://i.imgur.com/o3t4kLI.png)

##  KiUserExceptionDispatcher
This was the last function I referenced back to, and it was imported.

It prepares exception info passing `ExceptionRecord` into `rcx`, and `ExceptionContext` into `rdx`.
![Exception info preperation](https://i.imgur.com/f04dxG8.png)

Next, it calls `RtlDispatchException` and checks the result, if the result is true it calls `RtlGuardRestoreContext` (on x86 `ZwContinue`), which continues execution using information from `ExceptionContext`.
![Context restoration](https://i.imgur.com/SjUXW4e.png)

If the result evaluates to false (meaning no handlers continued execution) it calls `ZwRaiseException`, which will pass ExceptionCode and terminate the UM process.
![ZwRaiseException](https://i.imgur.com/coBk7D2.png)

## Updating
Self explanatory, go to `KiUserExceptionDispatcher`, subtract the `RtlDispatchException` call address from the start address, and update the offset.
Then go inside of `RtlDispatchException` and subtract the first `RtlpCallVectoredHandlers` call address from the start address, and update the offset.
