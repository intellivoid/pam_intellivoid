// Linux-includes for getting system info.
#include <arpa/inet.h>
#include <cerrno>
#include <map>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <iostream>
#include <fstream>
#include <array>
#include <string>
#include <vector>
#include <netdb.h>
#include <netinet/in.h>
#include <string>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/select.h> // also available via <sys/types.h>
#include <sys/socket.h>
#include <sys/statvfs.h> // For filesystem information
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h> // also available via <stdlib.h>
#include <sys/utsname.h>
#include <ifaddrs.h> // for getifaddrs
#include <net/if.h> // for IFF_UP
#include <linux/if_link.h> // for rtnl_link_stats
#include <unistd.h>

// For our defined types.
#include "libTitanium.h"
#include "statfs_types.h"

static char buf[8192];

inline std::string isolate(const std::string &haystack, const std::string &str1, const std::string &str2)
{
	size_t loc1 = haystack.find(str1) + 1;
	size_t loc2 = haystack.substr(loc1).find(str2);
	return haystack.substr(loc1, loc2);
}

inline std::vector<std::string> Tokenize(std::string && input, char delim = ' ')
{
	std::vector<std::string> tokens{};
	std::stringstream token_stream{input};

	std::string token;
	while (std::getline(token_stream, token, delim))
		tokens.push_back(token);

	return tokens; // copy elision
}

std::string NoTermColor(const std::string &ret)
{
	std::string str;
	bool in_term_color = false;

	for(auto & elem : ret)
	{
		char c = elem;

		if (in_term_color)
		{
			if(c == 'm')
				in_term_color = false;

			continue;
		}

		if (c == '\033')
		{
			in_term_color = true;
			continue;
		}

		if (!in_term_color)
			str += c;
	}

	return str;
}

std::pair<std::string, std::string> ParseKeyValue(std::string &&kvpair)
{
	size_t pos = kvpair.find("=");
	return std::make_pair(kvpair.substr(0, pos), kvpair.substr(pos+1));
}

bool FileExists(std::string && path)
{
	struct stat st;
	bzero(&st, sizeof(st));

	return stat(path.c_str(), &st) == 0;
}

///////////////////////////////////////////////////
// Function: GetKernInfo
//
// description:
// Parses several files to get kernel versions,
// when the kernel was built, what OS this is,
static int GetKernInfo(information_t *info)
{
	// Kernel information.
	struct utsname uts;
	if (uname(&uts) == -1)
	{
		perror("uname");
		return -1;
	}

	info->kernel_info.Version = strdup(uts.version);
	info->kernel_info.Release = strdup(uts.release);
	info->kernel_info.Type	= strdup(uts.sysname);

	// Get the hostname.
	info->Hostname = new char[HOST_NAME_MAX];
	if (gethostname(info->Hostname, HOST_NAME_MAX) == -1)
	{
		perror("gethostname");
		return -1;
	}

	FILE *f = fopen("/proc/sys/kernel/tainted", "r");
	if (!f)
		return -1;

	fscanf(f, "%hhd", &info->kernel_info.IsTainted);
	fclose(f);

	return 0;
}

///////////////////////////////////////////////////
// Function: GetLSBInfo
//
// description:
// Parses the information from /etc/lsb-release.
// It is optional to have this information included.
static int GetLSBInfo(information_t *info)
{
	FILE *f = fopen("/etc/lsb-release", "r");
	if (!f)
		return -1;

	info->lsb_info.Dist_id	 = reinterpret_cast<char *>(malloc(1024)); // Anyone who has a DISTRIB_ID longer than a kilobyte is retarded.
	info->lsb_info.Release	 = reinterpret_cast<char *>(malloc(1024)); // same as above
	info->lsb_info.Description = reinterpret_cast<char *>(malloc(1024));
	info->lsb_info.Version	 = reinterpret_cast<char *>(malloc(1024));

	while ((fgets(buf, sizeof(buf), f)))
	{
		sscanf(buf, "LSB_VERSION=%s", info->lsb_info.Version);
		sscanf(buf, "DISTRIB_ID=%s", info->lsb_info.Dist_id);
		sscanf(buf, "DISTRIB_RELEASE=%s", info->lsb_info.Release);
		sscanf(buf, "DISTRIB_DESCRIPTION=\"%s\"", info->lsb_info.Description);
	}

	fclose(f);
	return 0;
}

///////////////////////////////////////////////////
// Function: GetOSRelease
//
// description:
// Similar to GetLSBInfo, this gets information from
// /etc/os-release and tries to parse it. It will
// also handle special cases for certain popular
// distros which change the name away from os-release.
// Like GetLSBInfo this is also optional
static int GetOSRelease(information_t *info)
{
	char paths[][20] = {
		"/etc/os-release",
		"/etc/gentoo-release",
		"/etc/fedora-release",
		"/etc/redhat-release",
		"/etc/debian_version"
	};

	std::string pathfile, line;

	for (unsigned long i = 0; i < sizeof(paths) / 20; ++i)
	{
		if (!FileExists(paths[i]))
			continue;
		pathfile = paths[i];
	}

	if (pathfile.empty())
		return -1;

	std::ifstream versfile(pathfile, std::ios::in);
	if (!versfile.good())
		return -1;

	std::map<std::string, std::string> keyvals;

	while (std::getline(versfile, line))
	{
		auto [key, value] = ParseKeyValue(std::move(line));

		if (value[0] == '"' && value[value.length()-1] == '"')
			value = value.substr(1, value.length()-2);

		keyvals.try_emplace(key, value);
	}

	if (auto iter = keyvals.find("ID"); iter != keyvals.end()) 
		info->lsb_info.Dist_id = strdup(iter->second.c_str());
	if (auto iter = keyvals.find("PRETTY_NAME"); iter != keyvals.end()) 
		info->lsb_info.Description = strdup(iter->second.c_str());
	if (auto iter = keyvals.find("BUILD_ID"); iter != keyvals.end()) 
		info->lsb_info.Version = strdup(iter->second.c_str());

	if (!info->lsb_info.Version || !strlen(info->lsb_info.Version))
		info->lsb_info.Version = strdup("0.0");
	return 0;
}

///////////////////////////////////////////////////
// Function: GetMemoryInfo
//
// description:
// Parses /proc/meminfo for information on the RAM
// and swap usage. This also converts it from
// kilobytes to bytes.
static int GetMemoryInfo(information_t *info)
{
	FILE *data = fopen("/proc/meminfo", "r");
	if (!data)
		return -1;

	uint64_t TotalkBMemory, UsedkBMemory, FreekBMemory, AvailRam, SwapFree, SwapTotal;
	TotalkBMemory = FreekBMemory = UsedkBMemory = AvailRam = SwapFree = SwapTotal = 0;

	while (fgets(buf, sizeof(buf), data))
	{
		char *s = strstr(buf, "MemTotal: ");
		if (s)
			sscanf(s, "MemTotal: %lu kB\n", &TotalkBMemory);

		s = strstr(buf, "MemFree: ");
		if (s)
			sscanf(s, "MemFree: %lu kB", &FreekBMemory);

		s = strstr(buf, "MemAvailable:");
		if (s)
			sscanf(s, "MemAvailable: %lu kB\n", &AvailRam);

		s = strstr(buf, "SwapTotal:");
		if (s)
			sscanf(s, "SwapTotal: %lu kB\n", &SwapTotal);

		s = strstr(buf, "SwapFree:");
		if (s)
			sscanf(s, "SwapFree: %lu kB\n", &SwapFree);
	}

	// Get used memory.
	UsedkBMemory = TotalkBMemory - FreekBMemory;

	// Shift by 10 to get byte counts instead of kilobyte counts.
	info->memory_info.FreeRam   = (FreekBMemory << 10);
	info->memory_info.UsedRam   = (UsedkBMemory << 10);
	info->memory_info.TotalRam  = (TotalkBMemory << 10);
	info->memory_info.AvailRam  = (AvailRam << 10);
	info->memory_info.SwapFree  = (SwapFree << 10);
	info->memory_info.SwapTotal = (SwapTotal << 10);

	// cleanup and return.
	fclose(data);
	return 0;
}

static int GetCPUInfo(information_t *info)
{
	memset(&buf, 0, sizeof(buf));

	FILE *f = fopen("/proc/cpuinfo", "r");
	if (!f)
		return -1;

	while (fgets(buf, sizeof(buf), f))
	{
		std::string raw = buf;
		if (raw.find("model name") != std::string::npos)
		{
			// Make sure we're not allocated already.
			if (!info->cpu_info.Model)
				info->cpu_info.Model = strdup(raw.substr(13, raw.size() - 14).c_str());
		}
		// Adjust the cores value because linux does program readable and not human readable
		if (raw.find("processor") != std::string::npos)
			info->cpu_info.Cores = strtoul(raw.substr(12, raw.size() - 13).c_str(), nullptr, 10) + 1;
		if (raw.find("cpu cores") != std::string::npos)
			info->cpu_info.PhysicalCores = strtoul(raw.substr(12, raw.size() - 13).c_str(), nullptr, 10);
		if (raw.find("processor") != std::string::npos)
			info->cpu_info.CurrentSpeed = strtof(raw.substr(10, raw.size() - 11).c_str(), nullptr);
	}

	fclose(f);
	return 0;
}

static int GetDiskInfo(information_t *info)
{
	// Ref: https://www.kernel.org/doc/Documentation/filesystems/proc.txt
	// a line of self/mountinfo has the following structure:
	// 36  35  98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
	// (1) (2) (3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)
	//
	// (1) mount ID:  unique identifier of the mount (may be reused after umount)
	// (2) parent ID:  ID of parent (or of self for the top of the mount tree)
	// (3) major:minor:  value of st_dev for files on filesystem
	// (4) root:  root of the mount within the filesystem
	// (5) mount point:  mount point relative to the process's root
	// (6) mount options:  per mount options
	// (7) optional fields:  zero or more fields of the form "tag[:value]"
	// (8) separator:  marks the end of the optional fields
	// (9) filesystem type:  name of filesystem of the form "type[.subtype]"
	// (10) mount source:  filesystem specific information or "none"
	// (11) super options:  per super block options

	std::vector<std::string> lines;
	{
		std::ifstream mountinfo("/proc/self/mountinfo", std::ios::in);

		if (!mountinfo.good())
			return -1;

		for (std::string line; std::getline(mountinfo, line);)
			lines.push_back(std::move(line));
	}

	// Set the start point.
	hdd_info_t *head = new hdd_info_t, *iter = info->hdd_start = head, *last = nullptr;
	bzero(head, sizeof(hdd_info_t));

	for (auto && line : lines)
	{
		std::vector<std::string> tokens{Tokenize(std::move(line))};

		iter->MountPoint = strdup(tokens[4].c_str());
		iter->Opts       = strdup(tokens[5].c_str());
		iter->FSType     = strdup(tokens[8].c_str());
		iter->Device     = strdup(tokens[9].c_str());

		// Make a call to statvfs()
		struct statvfs vfs;
		if (statvfs(iter->MountPoint, &vfs) != 0)
			continue; // failed?

		iter->FSID       = vfs.f_fsid;
		iter->SpaceTotal = vfs.f_blocks * vfs.f_bsize;
		iter->SpaceFree  = vfs.f_bavail * vfs.f_bsize;
		iter->SpaceUsed  = (vfs.f_blocks - vfs.f_bfree) * vfs.f_bsize;
		iter->Inodes     = vfs.f_files;
		iter->InodesFree = vfs.f_ffree;
		iter->InodesUsed = vfs.f_files - vfs.f_ffree;
		iter->Blocks     = vfs.f_blocks;
		iter->BlockSize  = vfs.f_bsize;

		try
		{
			iter->Type = strdup(filesystems.at(vfs.f_fsid).FSType.c_str());
		}
		catch (const std::out_of_range &ex)
		{
		}

		iter->next = new hdd_info_t;
		bzero(iter->next, sizeof(hdd_info_t));
		last = iter;
		iter = iter->next;
	}

	delete last->next;
	last->next = nullptr;

	return 0;
}

///////////////////////////////////////////////////
// Function: GetLoadAvg
//
// description:
// This function gets the load averages. It also
// gets the last pid and a few scheduler stats
// which may be useful in the future (for now they
// are ignored).
static int GetLoadAvg(information_t *info)
{
	FILE *f = fopen("/proc/loadavg", "r");
	if (!f)
		return -1;

	unsigned int __attribute__((unused)) sched_runnable = 0;
	unsigned int __attribute__((unused)) sched_existed  = 0;
	pid_t __attribute__((unused)) lastpid				= 0;

	fscanf(f,
		   "%f %f %f %u/%u %lu",
		   &info->Loads[0],
		   &info->Loads[1],
		   &info->Loads[2],
		   &sched_runnable,
		   &sched_existed,
		   (unsigned long *)&lastpid);
	fclose(f);
	return 0;
}

///////////////////////////////////////////////////
// Function: GetStatisticalInfo
//
// description:
// This Function gets the CPU percentage, process
// count, processes active, time since boot in
// EPOCH format, and processes waiting on I/O.
static int GetStatisticalInfo(information_t *info)
{
	FILE *f = fopen("/proc/stat", "r");
	if (!f)
		return -1;

	unsigned long user_j, // Time spent in user mode
		nice_j,			  // Time spent in user mode with low priority
		sys_j,			  // Time spent in kernel space
		idle_j,			  // Time spent idling the CPU
		wait_j,			  // Time spent in waiting for I/O operations
		irq_j,			  // Time spent servicing interrupts
		sirq_j,			  // Time spent servcing softirqs
		stolen_j,		  // Time spent in other operating systems when running in a virtual environment
		guest_j,		  // Time spent running a virtual CPU for guests in KVM
		gnice_j;		  // Time spent running niced guest vCPU in KVM

	unsigned long user_k, // Time spent in user mode
		nice_k,			  // Time spent in user mode with low priority
		sys_k,			  // Time spent in kernel space
		idle_k,			  // Time spent idling the CPU
		wait_k,			  // Time spent in waiting for I/O operations
		irq_k,			  // Time spent servicing interrupts
		sirq_k,			  // Time spent servcing softirqs
		stolen_k,		  // Time spent in other operating systems when running in a virtual environment
		guest_k,		  // Time spent running a virtual CPU for guests in KVM
		gnice_k;		  // Time spent running niced guest vCPU in KVM

	// Differences.
	unsigned long diff_user, diff_system, diff_nice, diff_idle;

	// Get the information.
	while (fgets(buf, sizeof(buf), f))
	{
		sscanf(buf,
			   "cpu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
			   &user_j,
			   &nice_j,
			   &sys_j,
			   &idle_j,
			   &wait_j,
			   &irq_j,
			   &sirq_j,
			   &stolen_j,
			   &guest_j,
			   &gnice_j);
		// time since kernel started in EPOCH format
		sscanf(buf, "btime %lu", &info->StartTime);
		// Number of running processes on the system
		sscanf(buf, "processes %lu", &info->ProcessCount);
		// Number of ACTIVE running processes on the system
		sscanf(buf, "procs_running %lu", &info->RunningProcessCount);
		// Number of proceses waiting on system I/O operations.
		sscanf(buf, "procs_blocked %lu", &info->Zombies);
	}

	// Sleep while we wait for the kernel to do some stuff
	usleep(900000);

	// Now get it all again.
	fclose(f);
	f = fopen("/proc/stat", "r");
	fscanf(f,
		   "cpu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
		   &user_k,
		   &nice_k,
		   &sys_k,
		   &idle_k,
		   &wait_k,
		   &irq_k,
		   &sirq_k,
		   &stolen_k,
		   &guest_k,
		   &gnice_k);

	// Calculate the difference and produce a CPU percentage.
	diff_user   = user_k - user_j;
	diff_nice   = nice_k - nice_j;
	diff_system = sys_k - sys_j;
	diff_idle   = idle_k - idle_j;

	info->cpu_info.CPUPercent = (unsigned int)(((float)(diff_user + diff_nice + diff_system))
											   / ((float)(diff_user + diff_nice + diff_system + diff_idle)) * 100.0);

	fclose(f);
	return 0;
}

///////////////////////////////////////////////////
// Function: GetNetworkInfo
//
// description:
// Get the information on network adapters and
// how much data they have transferred.
static int GetNetworkInfo(information_t *info)
{
	struct ifaddrs *ifap = nullptr;
	if (getifaddrs(&ifap) != 0)
	{
		perror("getifaddrs");
		return -1;
	}

	// Use an std::map here to find interfaces multiple times
	std::map<std::string, network_info_t*> interfaces;

	typedef union {
		struct sockaddr sa;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} sockaddr_t;

	for (struct ifaddrs *ifiter = ifap; ifiter != nullptr; ifiter = ifiter->ifa_next)
	{
		// Determine what kind of info this is
		if (ifiter->ifa_addr == nullptr)
			continue;

		auto it = interfaces.find(ifiter->ifa_name);
		if (it == interfaces.end())
		{
			network_info_t *owo = new network_info_t;
			bzero(owo, sizeof(network_info_t));
			auto hmm = interfaces.emplace(std::string(ifiter->ifa_name), owo);
			owo->InterfaceName = strdup(ifiter->ifa_name);
			it = hmm.first;
		}

		network_info_t *iter = it->second;
		sockaddr_t *sok = reinterpret_cast<sockaddr_t*>(ifiter->ifa_addr);

		// ?????: I have no clue why these flags are like this
		// but this is required to get the correct flags.
		uint32_t flags = ifiter->ifa_flags & ~(1UL << 16);

		// if the interface is online and/or a loopback
		iter->Online = ((flags & IFF_UP) == IFF_UP) && ((flags & IFF_RUNNING) == IFF_RUNNING);
		iter->Loopback = ((flags & IFF_LOOPBACK) == IFF_LOOPBACK);

		// Handle interfaces that have IPv4 addresses
		switch(sok->sa.sa_family)
		{
			// TODO: support more than AF_INET and AF_INET6?
			case AF_INET:
			{
				inet_ntop(AF_INET, &sok->in.sin_addr, iter->IPv4Address, sizeof(iter->IPv4Address));
				break;
			}
			case AF_INET6:
			{
				inet_ntop(AF_INET6, &sok->in6.sin6_addr, iter->IPv6Address, sizeof(iter->IPv6Address));
				break;
			}
			case AF_PACKET:
			{
				if (ifiter->ifa_data == nullptr)
					break;
				struct rtnl_link_stats *stats = reinterpret_cast<struct rtnl_link_stats*>(ifiter->ifa_data);
				iter->TX = stats->tx_bytes;
				iter->RX = stats->rx_bytes;
				break;
			}
			default:
				break;
		}
	}
	freeifaddrs(ifap);

	// construct the linked list and return a head structure.
	network_info_t *head = nullptr, *iter = nullptr;
	for (auto && [key, value] : interfaces)
	{
		if (!head)
			iter = head = value;
		else 
			iter = iter->next = value;
	}

	info->net_start = head;
	return 0;
}

// Our C symbols.
extern "C"
{
	information_t *GetSystemInformation()
	{
		information_t *info = new information_t;
		bzero(info, sizeof(information_t));
		info->lsb_info.Dist_id = info->lsb_info.Version = info->lsb_info.Release = info->lsb_info.Description = nullptr;

		if (GetCPUInfo(info) != 0)
			goto fucked;

		if (GetLoadAvg(info) != 0)
			goto fucked;

		if (GetOSRelease(info) != 0)
		{
			if (GetLSBInfo(info) != 0)
			{
				// whatever.. we give up. It'll return a nullptr now.
			}
		}

		if (GetDiskInfo(info) != 0)
			goto fucked;

		if (GetMemoryInfo(info) != 0)
			goto fucked;

		if (GetStatisticalInfo(info) != 0)
			goto fucked;

		if (GetKernInfo(info) != 0)
			goto fucked;

		if (GetNetworkInfo(info) != 0)
			goto fucked;

		return info;
	fucked:
		delete info;
		return nullptr; 
	}

	void FreeSystemInformation(information_t *info) 
	{
		// Free ALL THE THINGS!
		free(info->lsb_info.Dist_id);
		free(info->lsb_info.Release);
		free(info->lsb_info.Description);
		free(info->lsb_info.Version);

		for (hdd_info_t *iter = info->hdd_start, *iterprev = nullptr; iter != nullptr; iterprev = iter, iter = iter->next)
		{
			free(iter->Device);
			free(iter->DeviceType);
			free(iter->MountPoint);
			free(iter->FSType);
			free(iter->Type);
			free(iter->Opts);
			delete iterprev;
		}
		
		for (network_info_t *iter = info->net_start, *iterprev = nullptr; iter != nullptr; iterprev = iter, iter = iter->next)
		{
			free(iter->InterfaceName);
			delete iterprev;
		}
		delete[] info->Hostname;
		free(info->kernel_info.Version);
		free(info->kernel_info.Release);
		free(info->kernel_info.Type);
		delete info;
	}
}
