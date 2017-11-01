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
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

// Include libembededFiglet
#include <Figlet.hh>
#include <iomanip>
#include <sstream>

// Include my future libTitanium library.
#include "libTitanium.h"

using namespace std::string_literals;

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
    char buf[0x200];
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
protected:
	char borderchar;
	size_t dividersize;
public:
	Message(const std::string &banner = "", const char borderchar = '+', size_t dividersize = 80) :
            message(banner), borderchar(borderchar), dividersize(dividersize)
	{
	}

	~Message()
	{
	}

	void AddLine(const std::string &key, const std::string &value)
	{
		// add the color, print the key and then the value with equals sign.
        char *tmp = nullptr;
		asprintf(&tmp, "\033[0;35m+  \033[0;37m%-15s \033[0;35m= \033[1;32m%s\033[0m\n", key.c_str(), value.c_str());
		this->message += tmp;
		free(tmp);
	}

	void AddSeparator(const std::string &str = "")
	{
		if (str.empty())
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
			size_t titlelen = str.length();
			size_t half = ((this->dividersize - titlelen) / 2) - 4;
			// Stupid fractional math doesn't do things the way we want so we have to
			// correct it to ensure all lengths are (roughly) the same.
			size_t lengthcorrection = this->dividersize - (titlelen + 4) - (half + half);

			// NOTE: you can always override the color in the title string given to this :3
			this->message += "\033[0;35m";
			this->message.insert(this->message.length(), half, this->borderchar);
			this->message += "[ \033[0;37m"s + str + "\033[0;35m ]"s;
			this->message.insert(this->message.length(), half + lengthcorrection, this->borderchar);
			this->message += "\033[0m\n";
		}
	}

	const char *GetString() { return this->message.c_str(); }


	// Used for generating random progress bars.
	static std::string GenerateProgressBar(double percentage, size_t length, const char *bordercolor = "\033[0;35m",
											const char *progresscolor = "\033[1;34m", char progresschar = '#', char leftborder = '[',
											char rightborder = ']')
	{
        // Initialize a string with spaces.
        std::string str = std::string(length, ' ');

        // Add our actual bar, overwriting the spaces.
        if (percentage != 0.0 && !isnan(percentage))
        {
            // Determine how many chars we need to replace as our `progresschar`
            size_t count = static_cast<size_t>(floor((percentage / 100.0f) * length));
            // Not sure why replace needs to know the end of the string and how many
            // chars to add... Seems kinda redundant to me but whatever.
            str.replace(0, count, count, progresschar);
        }

		// Use a string stream just because it's easier to rememebr how things go together.
		std::stringstream ss;
		// Get our formatted string (eg: [###           ])
		ss << bordercolor << leftborder << progresscolor << progresschar << str << bordercolor << rightborder;

		// All done! Just remember to free this string we return!
		return ss.str();
	}
};

static inline std::pair<size_t, const char*> GetHighestSize(size_t size)
{
	static const char *sizes[] = { "B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB" };
	int si = 0;
	for (; 1024 < size; si++, size >>= 10)
		;

	if (si > sizeof(sizes))
		return std::make_pair(0, "(Too Damn Big!)");
	else
		return std::make_pair(si, sizes[si]);
}

const char *idiotcheck(const char *idiot)
{
    return idiot ? idiot : "(Unknown)";
}

/* expected hook, this is where custom stuff happens */
int actuallyauth(pam_handle_t *pamh, int flags,int argc, const char **argv)
{
	information_t *info = GetSystemInformation();
    if (!info)
	   return PAM_BUF_ERR;

	// Figlet.
	std::stringstream ss;
	Figlet::banner.printFramed(info->Hostname, ss, Figlet::FIGLET_DOUBLE);

	Message msg("\033[1;32m"s + ss.str() + "\033[0m\n\n"s);
	msg.AddSeparator("System Data");
	msg.AddLine("Hostname", idiotcheck(info->Hostname));
	msg.AddLine("Address", idiotcheck(info->Hostname)); // FIXME!
	msg.AddLine("Kernel", std::string(info->kernel_info.Release) + " "s + std::string(info->kernel_info.Version));
	msg.AddLine("Uptime", mystrftime(info->StartTime, false));
    msg.AddLine("CPU", idiotcheck(info->cpu_info.Model));

    // Use stringstream for this because it's obnoxious otherwise.
    ss.str(""); ss.clear();
    ss << std::fixed << std::setprecision(2) << info->Loads[0] << " " << info->Loads[1] << " " << info->Loads[2];

	msg.AddLine("Load Avg.", ss.str());

    ss.str(""); ss.clear();
    ss << Message::GenerateProgressBar(info->cpu_info.CPUPercent, 20)
       << " \033[1;32m" << info->cpu_info.CPUPercent << "%\033[0m";
	msg.AddLine("CPU usage", ss.str());

	// We need to calculate our free memory usage and our used usage.
	// we calculate the amount used for the progress bar length and
	// the amount free for the actual percentage.
	double total = info->memory_info.TotalRam;
	double used  = info->memory_info.UsedRam;
    pam_syslog(pamh, LOG_INFO, "total = %f, used = %f", total, used);
	double freemem = ((total - used) / total) * 100.0f;
    double usedmem = (((used - total) / total) * 100.0f) + 100.0f;
    pam_syslog(pamh, LOG_INFO, "usedmem = %f, freemem = %f", usedmem, freemem);

	// Clear our string stream.
    ss.str(""); ss.clear();
    // Generate a progress bar that is 30 chars long.
    ss << Message::GenerateProgressBar(usedmem, 20) << " \033[1;32m" << usedmem << "% used";

	// Now add our line!
	msg.AddLine("Memory", ss.str());

	// Do our distro info.
	msg.AddSeparator("Distribution");
	msg.AddLine("Name", idiotcheck(info->lsb_info.Dist_id));
	msg.AddLine("Description", idiotcheck(info->lsb_info.Description));
	msg.AddLine("Release", idiotcheck(info->lsb_info.Release));
	msg.AddLine("Version", idiotcheck(info->lsb_info.Version));

	msg.AddSeparator("User Data");

	// Since we're pam, we can get the user we're trying to authenticate to.
	const char *user = nullptr;
	int pam_err = 0;
	if ((pam_err = pam_get_user(pamh, &user, nullptr)) != PAM_SUCCESS)
		user = "(Unknown)"; // wtf? why are we here?

	msg.AddLine("Username", user);

	// Get max children.
	long maxchild = sysconf(_SC_CHILD_MAX);
	msg.AddLine("Processes", std::to_string(info->ProcessCount) + " of "s + std::to_string(maxchild) + " MAX"s);
	msg.AddSeparator();

	// Print everything at login!
	pam_info(pamh, "%s", msg.GetString());

    FreeSystemInformation(info);

	return PAM_SUCCESS;
}

/* expected hook */
extern "C"
{
	PUBLIC_API int pam_sm_authenticate(pam_handle_t *pamh, int flags,int argc, const char **argv)
	{
		return actuallyauth(pamh, flags, argc, argv);
	}
	PUBLIC_API int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)       { return PAM_SUCCESS; }
	PUBLIC_API int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)     { return pam_sm_authenticate(pamh, flags, argc, argv); }
	PUBLIC_API int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)  { return PAM_SUCCESS; }
	PUBLIC_API int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
}
