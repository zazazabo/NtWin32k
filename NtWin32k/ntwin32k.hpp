#pragma once
#include "kutils.hpp"

#define WIN32K_SYSCALL_FILTER_MASK "xxxxxxxxxxxxxxxxxxxxxxx????xxx"
#define WIN32K_SYSCALL_FILTER_SIG "\x48\x89\x4C\x24\x20\x48\x89\x54\x24\x28\x4C\x89\x44\x24\x30\x4C\x89\x4C\x24\x38\x48\xC7\xC1\x00\x00\x00\x00\x48\xFF\x15"
static_assert(sizeof WIN32K_SYSCALL_FILTER_SIG == sizeof WIN32K_SYSCALL_FILTER_MASK, "signature and mask len invalid...");

typedef union _MISC_THREAD_VALUES
{
	struct
	{
		ULONG ThreadFlagsSpare : 2;                                       //0x78
		ULONG AutoAlignment : 1;                                          //0x78
		ULONG DisableBoost : 1;                                           //0x78
		ULONG AlertedByThreadId : 1;                                      //0x78
		ULONG QuantumDonation : 1;                                        //0x78
		ULONG EnableStackSwap : 1;                                        //0x78
		ULONG GuiThread : 1;                                              //0x78
		ULONG DisableQuantum : 1;                                         //0x78
		ULONG ChargeOnlySchedulingGroup : 1;                              //0x78
		ULONG DeferPreemption : 1;                                        //0x78
		ULONG QueueDeferPreemption : 1;                                   //0x78
		ULONG ForceDeferSchedule : 1;                                     //0x78
		ULONG SharedReadyQueueAffinity : 1;                               //0x78
		ULONG FreezeCount : 1;                                            //0x78
		ULONG TerminationApcRequest : 1;                                  //0x78
		ULONG AutoBoostEntriesExhausted : 1;                              //0x78
		ULONG KernelStackResident : 1;                                    //0x78
		ULONG TerminateRequestReason : 2;                                 //0x78
		ULONG ProcessStackCountDecremented : 1;                           //0x78
		ULONG RestrictedGuiThread : 1;                                    //0x78
		ULONG VpBackingThread : 1;                                        //0x78
		ULONG ThreadFlagsSpare2 : 1;                                      //0x78
		ULONG EtwStackTraceApcInserted : 8;                               //0x78
	};
	volatile LONG ThreadFlags;                                            //0x78
} MISC_THREAD_VALUES, * PMISC_THREAD_VALUES;

typedef struct _syscall_args_t
{
	u64 rcx, rdx, r8, r9;
} syscall_args_t, *psyscall_args_t;

inline void* original_function = nullptr;

// handler is designed to get the arguments passed in registers...
extern "C" void asm_hook_handler_2004(unsigned syscall_number);
extern "C" void asm_hook_handler(unsigned syscall_number);

namespace nt
{
	inline auto enable_filter(HANDLE tid) -> bool
	{
		PETHREAD thread;
		if (PsLookupThreadByThreadId(tid, &thread) == STATUS_SUCCESS)
		{
			const auto thread_misc_values =
				reinterpret_cast<PMISC_THREAD_VALUES>(
					reinterpret_cast<unsigned char*>(thread) + 0x78);

			// make the thread gui and restricted...
			thread_misc_values->GuiThread = 1;
			thread_misc_values->RestrictedGuiThread = 1;
			return true;
		}
		return false;
	}

	inline auto enable_filter(PETHREAD thread) -> void
	{
		const auto thread_misc_values =
			reinterpret_cast<PMISC_THREAD_VALUES>(
				reinterpret_cast<unsigned char*>(thread) + 0x78);

		// make the thread gui and restricted...
		thread_misc_values->GuiThread = 1;
		thread_misc_values->RestrictedGuiThread = 1;
	}

	namespace win32k
	{
		inline auto hook_filter(void* hook_func) -> void*
		{
			PEPROCESS peproc;
			KAPC_STATE apc_state;

			RTL_OSVERSIONINFOW version;
			RtlGetVersion(&version);

			const auto explorer_pid = kutils::process::get_pid(L"explorer.exe");
			PsLookupProcessByProcessId((HANDLE)explorer_pid, &peproc);

			// attach to an address space that contains win32k.sys
			KeStackAttachProcess(peproc, &apc_state);
			{
				const auto win32k = kutils::driver::get_driver_base("win32k.sys");
				if (version.dwBuildNumber >= 19041) // if 2004 and above...
				{
					/*
					*	.text:FFFFF97FFF0172E4 48 89 4C 24 20         mov     [rsp+48h+var_28], rcx
					*	.text:FFFFF97FFF0172E9 48 89 54 24 28         mov     [rsp+48h+var_20], rdx
					*	.text:FFFFF97FFF0172EE 4C 89 44 24 30         mov     [rsp+48h+var_18], r8
					*	.text:FFFFF97FFF0172F3 4C 89 4C 24 38         mov     [rsp+48h+var_10], r9
					*	.text:FFFFF97FFF0172F8 48 C7 C1 00 00 00 00   mov     rcx, 0          ; _QWORD
					*	.text:FFFFF97FFF0172FF 48 FF 15 [B2 A4 03 00] call    cs:__imp_IsWin32KSyscallFiltered <==== 30 bytes to this RVA...
					*/

					auto sig_result = reinterpret_cast<u64>(
						kutils::signature::scan(win32k,
							kutils::pe::get_nt_header(win32k)->OptionalHeader.SizeOfImage,
								WIN32K_SYSCALL_FILTER_SIG, WIN32K_SYSCALL_FILTER_MASK));

					const auto sig_rva = *reinterpret_cast<int*>(sig_result + 30); // + 30 from above...
					sig_result = sig_result + sig_rva + 34; // 34 bytes to RIP...

					if (sig_result)
					{
						/*
						*	.rdata:FFFFF97FFF0517B8                          ; __int64 (__fastcall *IsWin32KSyscallFiltered)(_QWORD)
						*	.rdata:FFFFF97FFF0517B8 E4 05 01 FF 7F F9 FF FF  __imp_IsWin32KSyscallFiltered dq offset IsWin32KSyscallFiltered <=== deference this....
						*/
						const auto win32k_filter_func = 
							reinterpret_cast<u64>(
								*reinterpret_cast<void**>(sig_result));

						/*
						*	.text:FFFFF97FFF0105E4   IsWin32KSyscallFiltered proc near
						*	.text:FFFFF97FFF0105E4 48 83 EC 28             sub     rsp, 28h
						*	.text:FFFFF97FFF0105E8 48 8B 05 [A1 67 05 00]  mov     rax, cs:qword_FFFFF97FFF066D90 <======= + 7 bytes to this RVA....
						*	.text:FFFFF97FFF0105EF 48 85 C0                test    rax, rax
						*	.text:FFFFF97FFF0105F2 74 06                   jz      short loc_FFFFF97FFF0105FA
						*	.text:FFFFF97FFF0105F4 FF 15 66 43 06 00       call    cs:__guard_dispatch_icall_fptr
						*/
						const auto ptr_swap_rva = *reinterpret_cast<int*>(win32k_filter_func + 7); // + 7 from above^
						const auto win32k_syscall_filter_ptr = reinterpret_cast<void**>(ptr_swap_rva + win32k_filter_func + 11); // + 7 because 11 bytes in is the next instruction after the mov rax, cs....
						const auto result = *win32k_syscall_filter_ptr;
						*win32k_syscall_filter_ptr = hook_func;

						KeUnstackDetachProcess(&apc_state);
						return result;
					}
				}
				else // else 1909 and below (IAT hook)...
				{
					auto result = kutils::driver::iat_hook(
						win32k, "IsWin32KSyscallFiltered", hook_func);

					KeUnstackDetachProcess(&apc_state);
					return result;
				}
			}
			KeUnstackDetachProcess(&apc_state);
			return nullptr;
		}

		inline auto unhook_filter(void* original_function) -> void
		{
			PEPROCESS peproc;
			KAPC_STATE apc_state;

			RTL_OSVERSIONINFOW version;
			RtlGetVersion(&version);

			const auto explorer_pid = kutils::process::get_pid(L"explorer.exe");
			PsLookupProcessByProcessId((HANDLE)explorer_pid, &peproc);

			// attach to an address space that contains win32k.sys
			KeStackAttachProcess(peproc, &apc_state);
			{
				const auto win32k = kutils::driver::get_driver_base("win32k.sys");
				if (version.dwBuildNumber >= 19041) // if 2004 and above...
				{
					/*
					*	.text:FFFFF97FFF0172E4 48 89 4C 24 20         mov     [rsp+48h+var_28], rcx
					*	.text:FFFFF97FFF0172E9 48 89 54 24 28         mov     [rsp+48h+var_20], rdx
					*	.text:FFFFF97FFF0172EE 4C 89 44 24 30         mov     [rsp+48h+var_18], r8
					*	.text:FFFFF97FFF0172F3 4C 89 4C 24 38         mov     [rsp+48h+var_10], r9
					*	.text:FFFFF97FFF0172F8 48 C7 C1 00 00 00 00   mov     rcx, 0          ; _QWORD
					*	.text:FFFFF97FFF0172FF 48 FF 15 [B2 A4 03 00] call    cs:__imp_IsWin32KSyscallFiltered <==== 30 bytes to this RVA...
					*/

					auto sig_result = reinterpret_cast<u64>(
						kutils::signature::scan(win32k,
							kutils::pe::get_nt_header(win32k)->OptionalHeader.SizeOfImage,
								WIN32K_SYSCALL_FILTER_SIG, WIN32K_SYSCALL_FILTER_MASK));

					const auto sig_rva = *reinterpret_cast<int*>(sig_result + 30); // + 30 from above...
					sig_result = sig_result + sig_rva + 34; // 34 bytes to RIP...

					if (sig_result)
					{
						/*
						*	.rdata:FFFFF97FFF0517B8                          ; __int64 (__fastcall *IsWin32KSyscallFiltered)(_QWORD)
						*	.rdata:FFFFF97FFF0517B8 E4 05 01 FF 7F F9 FF FF  __imp_IsWin32KSyscallFiltered dq offset IsWin32KSyscallFiltered <=== deference this....
						*/
						const auto win32k_filter_func =
							reinterpret_cast<u64>(
								*reinterpret_cast<void**>(sig_result));

						/*
						*	.text:FFFFF97FFF0105E4   IsWin32KSyscallFiltered proc near
						*	.text:FFFFF97FFF0105E4 48 83 EC 28             sub     rsp, 28h
						*	.text:FFFFF97FFF0105E8 48 8B 05 [A1 67 05 00]  mov     rax, cs:qword_FFFFF97FFF066D90 <======= + 7 bytes to this RVA....
						*	.text:FFFFF97FFF0105EF 48 85 C0                test    rax, rax
						*	.text:FFFFF97FFF0105F2 74 06                   jz      short loc_FFFFF97FFF0105FA
						*	.text:FFFFF97FFF0105F4 FF 15 66 43 06 00       call    cs:__guard_dispatch_icall_fptr
						*/
						const auto ptr_swap_rva = *reinterpret_cast<int*>(win32k_filter_func + 7); // + 7 from above^
						const auto win32k_syscall_filter_ptr = reinterpret_cast<void**>(ptr_swap_rva + win32k_filter_func + 11); // + 7 because 11 bytes in is the next instruction after the mov rax, cs....
						*win32k_syscall_filter_ptr = original_function;
					}
				}
				else // else 1909 and below (IAT hook)...
				{
					// restore IAT...
					kutils::driver::iat_hook(win32k, 
						"IsWin32KSyscallFiltered", original_function);
				}
			}
			KeUnstackDetachProcess(&apc_state);
		}
	}
}