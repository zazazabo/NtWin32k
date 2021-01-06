#include "ntwin32k.hpp"
#define SYSCALL_KEY 0xDEADBEEF

extern "C" auto hook_handler(unsigned syscall_num, psyscall_args_t args) -> bool
{
	if (args->rcx == SYSCALL_KEY)
	{
		DBG_PRINT("syscall number -> 0x%x\n", syscall_num);
		DBG_PRINT("		- rcx: 0x%p\n", args->rcx);
		DBG_PRINT("		- rdx: 0x%p\n", args->rdx);
		DBG_PRINT("		- r8: 0x%p\n", args->r8);
		DBG_PRINT("		- r9: 0x%p\n", args->r9);
		return true;
	}
	return false;
}

// unhook win32k filter on unload...
auto driver_unload(PDRIVER_OBJECT driver_object) -> void
{
	nt::win32k::unhook_filter(original_function);
}

auto driver_entry(
	PDRIVER_OBJECT	driver_object,
	PUNICODE_STRING registry_path
) -> NTSTATUS
{
	RTL_OSVERSIONINFOW version;
	RtlGetVersion(&version);

	if (version.dwBuildNumber >= 19041) // if 2004 and above...
		original_function = nt::win32k::hook_filter(&asm_hook_handler_2004);
	else
		original_function = nt::win32k::hook_filter(&asm_hook_handler);

	driver_object->DriverUnload = &driver_unload;
	return STATUS_SUCCESS;
}