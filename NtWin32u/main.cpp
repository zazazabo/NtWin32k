#include "ntwin32u.hpp"

int main()
{
	while (true)
	{
		std::printf("syscall result -> 0x%p\n", nt::win32u::syscall());
		std::getchar();
	}
}
