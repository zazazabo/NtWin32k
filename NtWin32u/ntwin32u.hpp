#pragma once
#include <Windows.h>
#include <winternl.h>
#include <map>
#include <string>
#include <time.h>
#include <atomic>
#include <vector>
#include <iostream>

namespace nt
{
	namespace win32u
	{
		using syscall_table_t = std::vector<std::pair<std::string, std::uintptr_t>>;
		inline syscall_table_t syscall_table = ([&]()-> syscall_table_t 
		{
			PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY syscall_policy{};
			syscall_policy.DisallowWin32kSystemCalls = true;

			std::printf("disable win32ksyscall -> %d\n", 
				SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy,
					&syscall_policy, sizeof syscall_policy));

			LoadLibraryA("user32.dll");
			syscall_table_t result;

			const auto win32u = 
				reinterpret_cast<PIMAGE_DOS_HEADER>(
					LoadLibraryA("win32u.dll"));
			
			const auto nt_header =
				reinterpret_cast<PIMAGE_NT_HEADERS64>(
					reinterpret_cast<std::uintptr_t>(win32u) + win32u->e_lfanew);

			const auto export_rvas = 
				nt_header->OptionalHeader.DataDirectory[
					IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

			const auto exports = 
				reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
					reinterpret_cast<std::uintptr_t>(win32u) + export_rvas);

			const auto name_rva = 
				reinterpret_cast<std::uint32_t*>(
					reinterpret_cast<std::uintptr_t>(win32u) + exports->AddressOfNames);

			for (auto idx = 0u; idx < exports->NumberOfNames; ++idx)
			{
				const auto function_name = 
					reinterpret_cast<const char*>(
						reinterpret_cast<std::uintptr_t>(win32u) + name_rva[idx]);

				// add Nt functions...
				if (!strncmp(function_name, "Nt", 2))
				{
					const auto func_rva = 
						reinterpret_cast<std::uint32_t*>(
							reinterpret_cast<std::uintptr_t>(win32u) + exports->AddressOfFunctions);

					const auto ordinal_rva =
						reinterpret_cast<std::uint16_t*>(
							reinterpret_cast<std::uintptr_t>(win32u) + exports->AddressOfNameOrdinals);

					const auto function_addr =
						reinterpret_cast<std::uintptr_t>(win32u) + func_rva[ordinal_rva[idx]];

					result.push_back({ function_name, function_addr });
				}
			}
			return result;
		})();

		inline auto syscall() -> std::uintptr_t
		{
			static const auto random = [&](int min, int max) -> int
			{
				if (static std::atomic<bool> first = false; !first.exchange(true))
					srand(time(NULL));

				return min + rand() % ((max + 1) - min);
			};

			const auto [function_name, function_addr] = 
				syscall_table[random(NULL, syscall_table.size())];

			std::printf("%s -> 0x%p\n", function_name.c_str(), function_addr);
			std::getchar();

			return reinterpret_cast<std::uintptr_t(*)(std::uintptr_t)>(function_addr)(0xC0FFEE);
		}
	}
}