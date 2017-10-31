#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <math.h>
#include <syslog.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

// Linux-includes for getting system info.
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/select.h>      // also available via <sys/types.h>
#include <sys/time.h>
#include <sys/types.h>       // also available via <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/statvfs.h>   // For filesystem information
#include <sys/utsname.h>

// Include libembededFiglet
#include <Figlet.hh>
#include <sstream>

using namespace std::string_literals;
// Temporary buffer for us to use
static char buf[8192];

typedef struct hdd_info_s
{
	// TODO
	char *Name; // Device/partition name.
	size_t BytesWritten;
	size_t BytesRead;

	size_t SpaceAvailable; // In bytes
	size_t SpaceUsed; // in bytes
	size_t PartitionSize; // in bytes
	char *MountPoint;
	char *FileSystemType; // NTFS or FAT32 on windows.
	struct hdd_info_s *next;
} hdd_info_t;

typedef struct network_info_s
{
	char *InterfaceName;
	char IPv6Address[INET6_ADDRSTRLEN];
	char IPv4Address[INET_ADDRSTRLEN];
	char MACAddress[17]; // Includes colons
	char SubnetMask[INET_ADDRSTRLEN]; // This is the IPv4 Subnet Mask and IPv6 CIDR mask
	uint64_t TX;
	uint64_t RX;
	struct network_info_s *next;
} network_info_t;

typedef struct information_s
{
	// CPU, RAM, Load time, Distro info, Uptime, Kernel Version, hard drive info,
	// # of total processes, # of active processes, # of users, hostname, current time, IPv4 Address(es),
	// IPv6 Address(es), Mac address(es), Interface names, TX/RX counts, subnet/cidr masks
	// kernel command line options (if available), CPU Architecture
	time_t CurrentTime;
	time_t StartTime; // Seconds in EPOCH format since the system booted.
	float Loads[3]; // Null on windows. -- for now.
	float SecondsIdle; // Seconds spent idle (idfk why the kernel gives it as a float)
	float SecondsUptime; // ???
	unsigned long ProcessCount;
	unsigned long RunningProcessCount;
	unsigned long Zombies;
	unsigned long UserCount;
	char *Hostname;

	struct
	{
		char *Architecture;   // arm, i386, x86_64, etc.
		char *Model;          // Model from the kernel (eg, Intel(R) Core(TM) i7-4930K CPU @ 3.40GHz)
		unsigned int Cores;         // How many logical processors the kernel sees (including hyperthreaded ones)
		unsigned int PhysicalCores; // How many physical cores exist on the die
		float CurrentSpeed;         // Current speed of the CPU.
		unsigned int CPUPercent;    // Calculated by us.
	} cpu_info;

	struct
	{
		uint64_t FreeRam; // In bytes
		uint64_t UsedRam; // In bytes
		uint64_t TotalRam; // In bytes
		uint64_t AvailRam; // In bytes, An estimate of how much memory is available for starting new applications
		uint64_t SwapFree; // In bytes
		uint64_t SwapTotal; // In bytes
	} memory_info;

	hdd_info_t *hdd_start;

	network_info_t *net_start;

	struct
	{
		char *Type;
		char *Version;
		char *Release;
		uint8_t IsTainted;
	} kernel_info;

	struct
	{
		char *Version;
		char *Dist_id;
		char *Release;
		char *Description;
	} lsb_info;
} information_t;

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
    info->kernel_info.Type = strdup(uts.sysname);

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

	fscanf(f, "%d", &info->kernel_info.IsTainted);
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

    info->lsb_info.Dist_id = reinterpret_cast<char *>(malloc(1024));     // Anyone who has a DISTRIB_ID longer than a kilobyte is retarded.
    info->lsb_info.Release = reinterpret_cast<char *>(malloc(1024));     // same as above
    info->lsb_info.Description = reinterpret_cast<char *>(malloc(1024));
    info->lsb_info.Version = reinterpret_cast<char *>(malloc(1024));

    while((fgets(buf, sizeof(buf), f)))
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
    FILE *data = fopen("/etc/os-release", "r");
    if (!data && (errno == EEXIST || errno == EACCES))
    {
        // Try to handle the special snowflake distros
        data = fopen("/etc/gentoo-release", "r");
        if (!data)
        {
            data = fopen("/etc/fedora-release", "r");
            if (!data)
            {
                data = fopen("/etc/redhat-release", "r");
                if (!data)
                {
                    data = fopen("/etc/debian_version", "r");
                    if (!data)
                        return -1; // Okay we're done. If you're this much of a special snowflake then you can go fuck yourself.
                }
            }
        }
    }
    else if (!data)
        return -1; // we failed and don't know why.

    info->lsb_info.Dist_id = reinterpret_cast<char *>(malloc(1024));
    info->lsb_info.Description = reinterpret_cast<char *>(malloc(1024));

    while (fgets(buf, sizeof(buf), data))
    {
        char *s = strstr("ID", buf);
        if (s)
            sscanf(s, "ID=\"%s\"", info->lsb_info.Dist_id);

        s = strstr("PRETTY_NAME", buf);
        if (s)
            sscanf(s, "PRETTY_NAME=\"%s\"", info->lsb_info.Description);
    }
    fclose(data);

    info->lsb_info.Dist_id = reinterpret_cast<char*>(realloc(info->lsb_info.Dist_id, strlen(info->lsb_info.Dist_id)+1));
    info->lsb_info.Description = reinterpret_cast<char*>(realloc(info->lsb_info.Description, strlen(info->lsb_info.Description)+1));
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
    info->memory_info.FreeRam = (FreekBMemory << 10);
    info->memory_info.UsedRam = (UsedkBMemory << 10);
    info->memory_info.TotalRam = (TotalkBMemory << 10);
    info->memory_info.AvailRam = (AvailRam << 10);
    info->memory_info.SwapFree = (SwapFree << 10);
    info->memory_info.SwapTotal = (SwapTotal << 10);

    // cleanup and return.
    fclose(data);
    return 0;
}

// Parse /proc/diskinfo
static int GetDiskInfo(information_t *info)
{
    memset(&buf, 0, sizeof(buf));

    FILE *f = fopen("/proc/diskstats", "r");
    if (!f)
    {
        perror("fopen");
        return -1;
    }

    #if 0
    Parsing the lines are fairly easy. The format of each line goes as follows:
    fields:
     1 - major number
     2 - minor mumber
     3 - device name
     4 - reads completed successfully
     5 - reads merged
     6 - sectors read
     7 - time spent reading (ms)
     8 - writes completed
     9 - writes merged
    10 - sectors written
    11 - time spent writing (ms)
    12 - I/Os currently in progress
    13 - time spent doing I/Os (ms)
    14 - weighted time spent doing I/Os (ms)
    Field  1 -- # of reads completed
        This is the total number of reads completed successfully.
    Field  2 -- # of reads merged, field 6 -- # of writes merged
        Reads and writes which are adjacent to each other may be merged for
        efficiency.  Thus two 4K reads may become one 8K read before it is
        ultimately handed to the disk, and so it will be counted (and queued)
        as only one I/O.  This field lets you know how often this was done.
    Field  3 -- # of sectors read
        This is the total number of sectors read successfully.
    Field  4 -- # of milliseconds spent reading
        This is the total number of milliseconds spent by all reads (as
        measured from __make_request() to end_that_request_last()).
    Field  5 -- # of writes completed
        This is the total number of writes completed successfully.
    Field  6 -- # of writes merged
        See the description of field 2.
    Field  7 -- # of sectors written
        This is the total number of sectors written successfully.
    Field  8 -- # of milliseconds spent writing
        This is the total number of milliseconds spent by all writes (as
        measured from __make_request() to end_that_request_last()).
    Field  9 -- # of I/Os currently in progress
        The only field that should go to zero. Incremented as requests are
        given to appropriate struct request_queue and decremented as they finish.
    Field 10 -- # of milliseconds spent doing I/Os
        This field increases so long as field 9 is nonzero.
    Field 11 -- weighted # of milliseconds spent doing I/Os
        This field is incremented at each I/O start, I/O completion, I/O
        merge, or read of these stats by the number of I/Os in progress
        (field 9) times the number of milliseconds spent doing I/O since the
        last update of this field.  This can provide an easy measure of both
        I/O completion time and the backlog that may be accumulating.
    #endif

    hdd_info_t *iter = NULL;
    info->hdd_start = iter = new hdd_info_t;

    while(fgets(buf, sizeof(buf), f))
    {
        // Variables
        uint32_t major, minor;
        size_t CompletedReads, MergedReads, SectorsRead, TimeSpentReading, CompletedWrites,
        MergedWrites, SectorsWritten, TimeSpentWriting, IOInProgress, TimeSpentIOProcessing,
        WeightedTimeSpentIOProcessing;
        char bufstr[sizeof(buf)];
        memset(bufstr, 0, sizeof(buf));

        // Get the data (yes this is nasty.)
        sscanf(buf, "%d %d %s %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld",
        &major, &minor, bufstr, &CompletedReads, &MergedReads, &SectorsRead, &TimeSpentReading,
        &CompletedWrites, &MergedWrites, &SectorsWritten, &TimeSpentWriting,
        &IOInProgress, &TimeSpentIOProcessing, &WeightedTimeSpentIOProcessing);

        // Fill out the struct.
        memset(iter, 0, sizeof(hdd_info_t));
        iter->Name = nullptr;
		iter->next = nullptr;

        printf("bufstr: %s\n", bufstr);

        iter->Name = strdup(bufstr);
        iter->BytesRead = CompletedReads;
        iter->BytesWritten = CompletedWrites;
        iter->next = new hdd_info_t;

        printf("HDD: %s\n", iter->Name);

        iter = iter->next;
    }

    // This is the end of the list.
    delete iter->next;
    iter->next = NULL;

    fclose(f);
    f = fopen("/proc/partitions", "r");
    if (!f)
    {
        perror("fopen");
        goto end;
    }

    // Parse /proc/partitions
    while (fgets(buf, sizeof(buf), f))
    {
        // the format of this file was a bit confusing but the procfs man page says
        // the format is as follows:
        // major  minor  1024-byte blockcnt    part-name
        //   8      0      3907018584             sda

        uint32_t major, minor;
        size_t blocks;
        char buffer[8192];
        memset(&buffer, 0, sizeof(buffer));

        // Skip 1st line.
        static int cnt = 0;
        if (!cnt)
        {
            cnt++;
            continue;
        }

        // Parse the values
        sscanf(buf, "%d, %d, %lu, %s", &major, &minor, &blocks, buffer);

        // make the byte count and add the value to the array.
        for (iter = info->hdd_start; iter; iter = iter->next)
        {
            printf("Looking for hdd... %s\n", iter->Name);
            if (!iter->Name)
                continue;
            if (!strcmp(iter->Name, buffer))
                iter->PartitionSize = blocks * 1024;
        }

    }
end:

    fclose(f);
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
    unsigned int __attribute__((unused)) sched_existed = 0;
    pid_t __attribute__((unused)) lastpid = 0;

    fscanf(f, "%f %f %f %u/%u %lu", &info->Loads[0], &info->Loads[1], &info->Loads[2], &sched_runnable, &sched_existed, (unsigned long*)&lastpid);
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
    nice_j,               // Time spent in user mode with low priority
    sys_j,                // Time spent in kernel space
    idle_j,               // Time spent idling the CPU
    wait_j,               // Time spent in waiting for I/O operations
    irq_j,                // Time spent servicing interrupts
    sirq_j,               // Time spent servcing softirqs
    stolen_j,             // Time spent in other operating systems when running in a virtual environment
    guest_j,              // Time spent running a virtual CPU for guests in KVM
    gnice_j;              // Time spent running niced guest vCPU in KVM

    unsigned long user_k, // Time spent in user mode
    nice_k,               // Time spent in user mode with low priority
    sys_k,                // Time spent in kernel space
    idle_k,               // Time spent idling the CPU
    wait_k,               // Time spent in waiting for I/O operations
    irq_k,                // Time spent servicing interrupts
    sirq_k,               // Time spent servcing softirqs
    stolen_k,             // Time spent in other operating systems when running in a virtual environment
    guest_k,              // Time spent running a virtual CPU for guests in KVM
    gnice_k;              // Time spent running niced guest vCPU in KVM

    // Differences.
    unsigned long diff_user, diff_system, diff_nice, diff_idle;

    // Get the information.
    while(fgets(buf, sizeof(buf), f))
    {
        sscanf(buf, "cpu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu", &user_j, &nice_j, &sys_j, &idle_j, &wait_j, &irq_j, &sirq_j, &stolen_j, &guest_j, &gnice_j);
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
    fscanf(f, "cpu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu", &user_k, &nice_k, &sys_k, &idle_k, &wait_k, &irq_k, &sirq_k, &stolen_k, &guest_k, &gnice_k);

    // Calculate the difference and produce a CPU percentage.
    diff_user = user_k - user_j;
    diff_nice = nice_k - nice_j;
    diff_system = sys_k - sys_j;
    diff_idle = idle_k - idle_j;

    info->cpu_info.CPUPercent = (unsigned int)(((float)(diff_user + diff_nice + diff_system))/((float)(diff_user + diff_nice + diff_system + diff_idle))*100.0);

    fclose(f);
    return 0;
}


std::string Duration(time_t t)
{
	/* We first calculate everything */
	time_t years = t / 31536000;
	time_t days = (t / 86400) % 365;
	time_t hours = (t / 3600) % 24;
	time_t minutes = (t / 60) % 60;
	time_t seconds = (t) % 60;

	if (!years && !days && !hours && !minutes)
		return std::to_string(seconds) + " "s + (seconds != 1 ? "seconds"s : "second"s);
	else
	{
		bool need_comma = false;
		std::string buffer;
		if (years)
		{
			buffer = std::to_string(years) + " "s + (years != 1 ? "years"s : "year"s);
			need_comma = true;
		}
		if (days)
		{
			buffer += need_comma ? ", " : "";
			buffer += std::to_string(days) + " "s + (days != 1 ? "days"s : "day"s);
			need_comma = true;
		}
		if (hours)
		{
			buffer += need_comma ? ", " : "";
			buffer += std::to_string(hours) + " "s + (hours != 1 ? "hours"s : "hour"s);
			need_comma = true;
		}
		if (minutes)
		{
			buffer += need_comma ? ", " : "";
			buffer += std::to_string(minutes) + " "s + (minutes != 1 ? "minutes"s : "minute"s);
		}
		return buffer;
	}
}

std::string mystrftime(time_t t, bool short_output)
{
	tm tm = *localtime(&t);
	time_t CurTime = time(nullptr);
	strftime(buf, sizeof(buf), "%b %d %H:%M:%S %Y %Z", &tm);
	if (short_output)
		return buf;
	if (t < CurTime)
		return std::string(buf) + " ("s + Duration(CurTime - t) + " ago)"s;
	else if (t > CurTime)
		return std::string(buf) + " ("s + Duration(t - CurTime) + " from now)"s;
	else
		return std::string(buf) + " (now)"s;
}



class Message
{
	std::string message;
	char *tmp;
protected:
	char borderchar;
	size_t dividersize;
public:
	Message(const char *banner = nullptr, const char borderchar = '+', size_t dividersize = 80) : message(banner), borderchar(borderchar), dividersize(dividersize)
	{
	}

	~Message()
	{
	}

	void AddLine(const char *key, const char* value)
	{
		// add the color, print the key and then the value with equals sign.
		asprintf(&this->tmp, "\033[0;35m+  \033[0;37m%-15s \033[0;35m= \033[1;32m%s\033[0m\n", key, value);
		this->message += this->tmp;
		free(this->tmp);
		this->tmp = nullptr;
	}

	void AddSeparator(const char *title = nullptr)
	{
		if (!title)
		{
			this->message += "\033[0;35m";
			this->message.insert(this->message.length(), this->dividersize, this->borderchar);
			this->message += "\033[0m\n";
		}
		else
		{
			// We have to actually calculate this.
			// First, take our divider size then subtract the length of the title minus 4 for colons and spaces.
			// We divide by two because we have two sides of the line.
			size_t titlelen = strlen(title);
			size_t half = ((this->dividersize - titlelen) / 2) - 4;
			// Stupid fractional math doesn't do things the way we want so we have to
			// correct it to ensure all lengths are (roughly) the same.
			size_t lengthcorrection = this->dividersize - (titlelen + 4) - (half + half);

			// NOTE: you can always override the color in the title string given to this :3
			this->message += "\033[0;35m";
			this->message.insert(this->message.length(), half, this->borderchar);
			this->message += "[ \033[0;37m"s + std::string(title) + "\033[0;35m ]"s;
			this->message.insert(this->message.length(), half + lengthcorrection, this->borderchar);
			this->message += "\033[0m\n";
		}
	}

	const char *GetString() { return this->message.c_str(); }


	// Used for generating random progress bars.
	static std::string GenerateProgressBar(pam_handle_t *pamh, double percentage, size_t length, const char *bordercolor = "\033[0;35m",
											const char *progresscolor = "\033[1;34m", char progresschar = '#', char leftborder = '[',
											char rightborder = ']')
	{
		// Allocate the bar space requested + null terminator
		char *str = new char[length + 1];

		// First, initialize as all spaces
		memset(str, ' ', length);
		// Make sure it's an appropriate number to use
		if (percentage != 0.0 && !isnan(percentage)) // Now calculate our progress bar length and set the char.
			memset(str, progresschar, (size_t)floor((percentage / 100.0f) * length));

		// Terminate the string.
		str[length-1] = 0;

		// asprintf is too fucking retarded to figure out how the fuck to allocate and use
		// a string so we have to do shit manually. Never send a machine to do a machine's
		// job apparently. This shit is fucking retarded. Can't believe I had to use a
		// damn string stream where printf formatting would've worked fine.
		std::stringstream ss;
		// Get our formatted string (eg: [###           ])
		ss << bordercolor << leftborder << progresscolor << progresschar << str << bordercolor << rightborder;

		// Free our memory
		delete [] str;

		// All done! Just remember to free this string we return!
		return ss.str();
	}
};

static inline const char *GetHighestSize(size_t *size)
{
	static const char *sizes[] = { "B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB" };
	int si = 0;
	for (; 1024 < *size; si++, *size >>= 10)
		;

	if (si > sizeof(sizes))
		return "(Too Damn Big!)";
	else
		return sizes[si];
}

/* expected hook, this is where custom stuff happens */
int actuallyauth(pam_handle_t *pamh, int flags,int argc, const char **argv)
{
	information_t *info = new information_t;
	memset(info, 0, sizeof(information_t));

	if (GetLoadAvg(info) != 0)
		goto fucked;

	if (GetLoadAvg(info) != 0)
    	goto fucked;

    if (GetLSBInfo(info) != 0)
    {
        if (GetOSRelease(info) != 0)
        {
            // Allocate a string so we don't free non-freeable memory.
            char * stupid = new char[sizeof("Unknown") + 1];
			strcpy(stupid, "Unknown");
            info->lsb_info.Dist_id = info->lsb_info.Version =
            info->lsb_info.Release = info->lsb_info.Description = stupid;
        }
    }

    // TODO: Unfuck this function
    //if (GetDiskInfo(info) != 0)
    //    goto fail;

    if (GetMemoryInfo(info) != 0)
        goto fucked;

    if (GetStatisticalInfo(info) != 0)
        goto fucked;

    if (GetKernInfo(info) != 0)
        goto fucked;

	goto bypass;
fucked:
	delete info;
	return PAM_BUF_ERR;

bypass:
	// Figlet.
	std::stringstream ss;
	Figlet::banner.printFramed(info->Hostname, ss, Figlet::FIGLET_DOUBLE);

	Message msg(std::string(ss.str() + "\n\n").c_str());
	msg.AddSeparator("System Data");
	msg.AddLine("Hostname", info->Hostname);
	msg.AddLine("Address", info->Hostname); // FIXME!
	msg.AddLine("Kernel", std::string(std::string(info->kernel_info.Release) + " "s + std::string(info->kernel_info.Version)).c_str());
	msg.AddLine("Uptime", mystrftime(info->StartTime, false).c_str());
	msg.AddLine("CPU", info->cpu_info.Model);
	msg.AddLine("CPU usage", (std::to_string(info->cpu_info.CPUPercent) + " %"s).c_str());
	msg.AddLine("Load Avg.", (std::to_string(info->Loads[0]).substr(0,4) + " "s +
								std::to_string(info->Loads[1]).substr(0,4) + " "s + std::to_string(info->Loads[2]).substr(0,4)).c_str());

	// We need to calculate our free memory usage and our used usage.
	// we calculate the amount used for the progress bar length and
	// the amount free for the actual percentage.
	double total = info->memory_info.TotalRam;
	double used  = info->memory_info.UsedRam;
	double usedmem = ((total - used) / total) * 100.0f;

	// Generate a progress bar that is 30 chars long.
	std::string bar = Message::GenerateProgressBar(pamh, usedmem, 30);

	// Now we need to add our percentage.
	char *donestr = nullptr;
	asprintf(&donestr, "%s \033[1;32m%.2f%% used", bar.c_str(), usedmem);

	// Now add our line!
	msg.AddLine("Memory", donestr);
	free (reinterpret_cast<void*>(donestr));

	// Do our distro info.
	msg.AddSeparator("Distribution");
	msg.AddLine("Name", info->lsb_info.Dist_id);
	msg.AddLine("Description", info->lsb_info.Description);
	msg.AddLine("Release", info->lsb_info.Release);
	msg.AddLine("Version", info->lsb_info.Version);

	msg.AddSeparator("User Data");

	// Since we're pam, we can get the user we're trying to authenticate to.
	const char *user = nullptr;
	int pam_err = 0;
	if ((pam_err = pam_get_user(pamh, &user, nullptr)) != PAM_SUCCESS)
		user = "(Unknown)"; // wtf? why are we here?

	msg.AddLine("Username", user);

	// Get max children.
	long maxchild = sysconf(_SC_CHILD_MAX);
	msg.AddLine("Processes", std::string(std::to_string(info->ProcessCount) + " of "s + std::to_string(maxchild) + " MAX"s).c_str());
	msg.AddSeparator();

	// Print everything at login!
	pam_info(pamh, "%s", msg.GetString());

	// Free ALL THE THINGS!
	free(reinterpret_cast<void*>(info->lsb_info.Dist_id));      info->lsb_info.Dist_id     = nullptr;
	free(reinterpret_cast<void*>(info->lsb_info.Release));      info->lsb_info.Release     = nullptr;
	free(reinterpret_cast<void*>(info->lsb_info.Description));  info->lsb_info.Description = nullptr;
	free(reinterpret_cast<void*>(info->lsb_info.Version));      info->lsb_info.Version     = nullptr;
	for (hdd_info_t *iter = info->hdd_start; iter; )
	{
		// Ensure we can iterate.
		hdd_info_t *iterprev = iter;
		iter = iter->next;
		free(reinterpret_cast<void*>(iterprev->Name));
		delete iterprev;
	}
	delete info->Hostname;
	free(reinterpret_cast<void*>(info->kernel_info.Version)); info->kernel_info.Version = nullptr;
	free(reinterpret_cast<void*>(info->kernel_info.Release)); info->kernel_info.Release = nullptr;
	free(reinterpret_cast<void*>(info->kernel_info.Type));    info->kernel_info.Type    = nullptr;
	delete info;


	return PAM_SUCCESS;
}

/* expected hook */
extern "C"
{
	int pam_sm_authenticate(pam_handle_t *pamh, int flags,int argc, const char **argv)
	{
		return actuallyauth(pamh, flags, argc, argv);
	}
	int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)       { return PAM_SUCCESS; }
	int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)     { return pam_sm_authenticate(pamh, flags, argc, argv); }
	int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)  { return PAM_SUCCESS; }
	int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
}
