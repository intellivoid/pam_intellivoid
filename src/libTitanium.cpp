// Linux-includes for getting system info.
#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <climits>
#include <cerrno>
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
#include <string>

// For our defined types.
#include "libTitanium.h"

static char buf[8192];

inline std::string isolate(const std::string &haystack, const std::string &str1, const std::string &str2)
{
    size_t loc1 = haystack.find(str1) + 1;
    size_t loc2 = haystack.substr(loc1).find(str2);
    return haystack.substr(loc1, loc2);
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
    errno = 0;
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
    bzero(info->lsb_info.Description, 1024);
    bzero(info->lsb_info.Dist_id, 1024);

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

static int GetCPUInfo(information_t *info)
{
    memset(&buf, 0, sizeof(buf));

    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f)
        return -1;

    while(fgets(buf, sizeof(buf), f))
    {
        std::string raw = buf;
        if (raw.find("model name") != std::string::npos)
        {
            // Make sure we're not allocated already.
            if (!info->cpu_info.Model)
                info->cpu_info.Model = strdup(raw.substr(13, raw.size()-14).c_str());
        }
        // Adjust the cores value because linux does program readable and not human readable
        if (raw.find("processor") != std::string::npos)
            info->cpu_info.Cores = strtoul(raw.substr(12, raw.size()-13).c_str(), nullptr, 10) + 1;
        if (raw.find("cpu cores") != std::string::npos)
            info->cpu_info.PhysicalCores = strtoul(raw.substr(12, raw.size()-13).c_str(), nullptr, 10);
        if (raw.find("processor") != std::string::npos)
            info->cpu_info.CurrentSpeed = strtof(raw.substr(10, raw.size()-11).c_str(), nullptr);
    }

    fclose(f);
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
        iter->Name = strdup(bufstr);
        iter->BytesRead = CompletedReads;
        iter->BytesWritten = CompletedWrites;
        iter->next = new hdd_info_t;

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

// Returns an allocated system information structure.
information_t *__GetSystemInformation()
{
    information_t *info = new information_t;
    bzero(info, sizeof(information_t));
    info->lsb_info.Dist_id = info->lsb_info.Version =
    info->lsb_info.Release = info->lsb_info.Description = nullptr;

    if (GetCPUInfo(info) != 0)
        goto fucked;

    if (GetLoadAvg(info) != 0)
        goto fucked;

    if (GetLSBInfo(info) != 0)
    {
        if (GetOSRelease(info) != 0)
        {
            // whatever.. we give up. It'll return a nullptr now.
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

    return info;
fucked:
    delete info;
    return nullptr;
}

// bypass C++ typesafety because we're trying to be a C library.
#define FreeAndClear(x) free(reinterpret_cast<void*>(x)); x = nullptr

void __FreeSystemInformation(information_t *info)
{
    // Free ALL THE THINGS!
    FreeAndClear(info->lsb_info.Dist_id);
    FreeAndClear(info->lsb_info.Release);
    FreeAndClear(info->lsb_info.Description);
    FreeAndClear(info->lsb_info.Version);
	for (hdd_info_t *iter = info->hdd_start; iter; )
	{
		// Ensure we can iterate.
		hdd_info_t *iterprev = iter;
		iter = iter->next;
        FreeAndClear(iterprev->Name);
		delete iterprev;
	}
	delete [] info->Hostname;
    FreeAndClear(info->kernel_info.Version);
    FreeAndClear(info->kernel_info.Release);
    FreeAndClear(info->kernel_info.Type);
	delete info;
}

// Our C symbols.
extern "C"
{
    information_t *GetSystemInformation() { return __GetSystemInformation(); }
    void FreeSystemInformation(information_t *info) { __FreeSystemInformation(info); }
}
