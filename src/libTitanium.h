#pragma once
#include <netinet/in.h>

#define PUBLIC_API __attribute__((visibility("default")))

extern "C"
{
	typedef struct PUBLIC_API hdd_info_s
	{
		char *             Device;
		char *             DeviceType;
		char *             MountPoint;
		char *             FSType;
		char *             Type;
		char *             Opts;
		uint32_t           FSID;
		uint64_t           SpaceTotal;
		uint64_t           SpaceFree;
		uint64_t           SpaceUsed;
		uint64_t           Inodes;
		uint64_t           InodesFree;
		uint64_t           InodesUsed;
		uint64_t           Blocks;
		uint64_t           BlockSize;
		// TODO
		size_t             BytesWritten;
		size_t             BytesRead;
		struct hdd_info_s *next;
	} hdd_info_t;

	typedef struct PUBLIC_API network_info_s
	{
		char *                 InterfaceName;
		char                   IPv6Address[INET6_ADDRSTRLEN];
		char                   IPv4Address[INET_ADDRSTRLEN];
		char                   MACAddress[17]; // Includes colons
		uint64_t               TX;
		uint64_t               RX;
		uint8_t                Online;   // Whether the device is Up or Down
		uint8_t                Loopback; // Whether the device is a loopback device
		struct network_info_s *next;
	} network_info_t;

	typedef struct PUBLIC_API information_s
	{
		// CPU, RAM, Load time, Distro info, Uptime, Kernel Version, hard drive info,
		// # of total processes, # of active processes, # of users, hostname, current time, IPv4 Address(es),
		// IPv6 Address(es), Mac address(es), Interface names, TX/RX counts, subnet/cidr masks
		// kernel command line options (if available), CPU Architecture
		time_t        CurrentTime;
		time_t        StartTime;     // Seconds in EPOCH format since the system booted.
		float         Loads[3];      // Null on windows. -- for now.
		float         SecondsIdle;   // Seconds spent idle (idfk why the kernel gives it as a float)
		float         SecondsUptime; // ???
		unsigned long ProcessCount;
		unsigned long RunningProcessCount;
		unsigned long Zombies;
		unsigned long UserCount;
		char *        Hostname;

		struct PUBLIC_API
		{
			char *       Architecture;  // arm, i386, x86_64, etc.
			char *       Model;         // Model from the kernel (eg, Intel(R) Core(TM) i7-4930K CPU @ 3.40GHz)
			unsigned int Cores;         // How many logical processors the kernel sees (including hyperthreaded ones)
			unsigned int PhysicalCores; // How many physical cores exist on the die
			float        CurrentSpeed;  // Current speed of the CPU.
			unsigned int CPUPercent;    // Calculated by us.
		} cpu_info;

		struct PUBLIC_API
		{
			uint64_t FreeRam;   // In bytes
			uint64_t UsedRam;   // In bytes
			uint64_t TotalRam;  // In bytes
			uint64_t AvailRam;  // In bytes, An estimate of how much memory is available for starting new applications
			uint64_t SwapFree;  // In bytes
			uint64_t SwapTotal; // In bytes
		} memory_info;

		hdd_info_t *    hdd_start;

		network_info_t *net_start;

		struct PUBLIC_API
		{
			char *  Type;
			char *  Version;
			char *  Release;
			uint8_t IsTainted;
		} kernel_info;

		struct PUBLIC_API
		{
			char *Version;
			char *Dist_id;
			char *Release;
			char *Description;
		} lsb_info;
	} information_t;

	// Function definitions.
	// Our C symbols.

	extern PUBLIC_API information_t *GetSystemInformation();
	extern PUBLIC_API void           FreeSystemInformation(information_t *info);
}
