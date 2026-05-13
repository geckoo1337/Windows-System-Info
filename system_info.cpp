#define _WIN32_DCOM
#include <windows.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <fstream>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <locale>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "wbemuuid.lib")

struct WmiField {
    const wchar_t* name;
    const wchar_t* label;
};
// A stream buffer that duplicates output to two underlying buffers (e.g., console and stringstream).
class TeeWBuffer : public std::wstreambuf {
public:
    TeeWBuffer(std::wstreambuf* first, std::wstreambuf* second)
        : first_(first), second_(second) {}
	// Override overflow to write characters to both buffers.
protected:
    int_type overflow(int_type ch) override {
        if (ch == traits_type::eof()) return traits_type::not_eof(ch);
        const auto c = static_cast<wchar_t>(ch);
        const auto r1 = first_->sputc(c);
        const auto r2 = second_->sputc(c);
        return (r1 == traits_type::eof() || r2 == traits_type::eof()) ? traits_type::eof() : ch;
    }
	// Override sync to flush both buffers.
    int sync() override {
        const int r1 = first_->pubsync();
        const int r2 = second_->pubsync();
        return (r1 == 0 && r2 == 0) ? 0 : -1;
    }

private:
    std::wstreambuf* first_;
    std::wstreambuf* second_;
};
// Convert a VARIANT value to a human-readable string, handling common types and arrays.
std::wstring VariantToString(const VARIANT& value) {
    if (value.vt == VT_NULL || value.vt == VT_EMPTY) return L"";

    if ((value.vt & VT_ARRAY) && (value.vt & VT_BSTR)) {
        SAFEARRAY* array = value.parray;
        LONG lower = 0, upper = -1;
        if (FAILED(SafeArrayGetLBound(array, 1, &lower)) ||
            FAILED(SafeArrayGetUBound(array, 1, &upper))) {
            return L"";
        }

        std::wstringstream out;
        for (LONG i = lower; i <= upper; ++i) {
            BSTR item = nullptr;
            if (SUCCEEDED(SafeArrayGetElement(array, &i, &item))) {
                if (i > lower) out << L", ";
                out << (item ? item : L"");
                SysFreeString(item);
            }
        }
        return out.str();
    }

    VARIANT converted;
    VariantInit(&converted);
    if (SUCCEEDED(VariantChangeType(&converted, const_cast<VARIANT*>(&value), 0, VT_BSTR))) {
        std::wstring result = converted.bstrVal ? converted.bstrVal : L"";
        VariantClear(&converted);
        return result;
    }

    return L"[unconverted type]";
}
// Convert bytes to a human-readable string in GiB with two decimal places.
std::wstring BytesToGiB(unsigned long long bytes) {
    std::wstringstream out;
    out << std::fixed << std::setprecision(2)
        << static_cast<long double>(bytes) / 1024.0L / 1024.0L / 1024.0L
        << L" GiB";
    return out.str();
}
// Convert a boolean value to "Yes" or "No" at the end of processing.
std::wstring BoolText(bool value) {
    return value ? L"Yes" : L"No";
}
// Print a label and value in a formatted way, skipping empty values.
void PrintLine(const std::wstring& label, const std::wstring& value) {
    if (!value.empty()) {
        std::wcout << L"  " << std::left << std::setw(34) << label << L": " << value << L"\n";
    }
}
// Get an environment variable value, returning an empty string if it doesn't exist.
const wchar_t* GetEnvValue(const wchar_t* name) {
    const wchar_t* value = _wgetenv(name);
    return value ? value : L"";
}
// Generate a report file name based on the current date and time.
std::wstring MakeReportFileName() {
    SYSTEMTIME now;
    GetLocalTime(&now);

    std::wstringstream name;
    name << L"system_info_"
         << now.wYear
         << std::setw(2) << std::setfill(L'0') << now.wMonth
         << std::setw(2) << std::setfill(L'0') << now.wDay
         << L"_"
         << std::setw(2) << std::setfill(L'0') << now.wHour
         << std::setw(2) << std::setfill(L'0') << now.wMinute
         << std::setw(2) << std::setfill(L'0') << now.wSecond
         << L".txt";
    return name.str();
}
// Save the report string to a file, returning true on success.
bool SaveReportToFile(const std::wstring& path, const std::wstring& report) {
    std::wofstream file(path);
    if (!file) return false;

    file.imbue(std::locale(""));
    file << report;
    return static_cast<bool>(file);
}
// A helper class to manage WMI connections and queries, ensuring proper cleanup of COM interfaces.
class WmiConnection {
public:
    ~WmiConnection() {
        if (services_) services_->Release();
        if (locator_) locator_->Release();
    }

    bool Connect(const wchar_t* nameSpace = L"ROOT\\CIMV2", bool verbose = true) {
        HRESULT hr = CoCreateInstance(
            CLSID_WbemLocator,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            reinterpret_cast<void**>(&locator_));

        if (FAILED(hr)) {
            if (verbose) std::wcerr << L"Failed to create IWbemLocator: 0x" << std::hex << hr << L"\n";
            return false;
        }

        BSTR ns = SysAllocString(nameSpace);
        hr = locator_->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services_);
        SysFreeString(ns);

        if (FAILED(hr)) {
            if (verbose) std::wcerr << L"Failed to connect to WMI namespace " << nameSpace << L": 0x" << std::hex << hr << std::dec << L"\n";
            return false;
        }
		// Set the proxy blanket to use the current security context for WMI calls.
        hr = CoSetProxyBlanket(
            services_,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            nullptr,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE);

        if (FAILED(hr)) {
            if (verbose) std::wcerr << L"Failed to set WMI proxy blanket: 0x" << std::hex << hr << std::dec << L"\n";
            return false;
        }

        return true;
    }
	// Execute a WMI query and print the specified fields with labels.
    void QueryAndPrint(const std::wstring& title, const wchar_t* wql, const std::vector<WmiField>& fields) {
        std::wcout << L"\n=== " << title << L" ===\n";

        IEnumWbemClassObject* enumerator = nullptr;
        BSTR language = SysAllocString(L"WQL");
        BSTR query = SysAllocString(wql);

        HRESULT hr = services_->ExecQuery(
            language,
            query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr,
            &enumerator);

        SysFreeString(language);
        SysFreeString(query);

        if (FAILED(hr)) {
            std::wcerr << L"  WMI query failed: 0x" << std::hex << hr << std::dec << L"\n";
            return;
        }

        ULONG returned = 0;
        IWbemClassObject* object = nullptr;
        int index = 0;

        while (enumerator && enumerator->Next(WBEM_INFINITE, 1, &object, &returned) == S_OK) {
            if (index++ > 0) std::wcout << L"\n";

            for (const auto& field : fields) {
                VARIANT value;
                VariantInit(&value);
                if (SUCCEEDED(object->Get(field.name, 0, &value, nullptr, nullptr))) {
                    PrintLine(field.label, VariantToString(value));
                }
                VariantClear(&value);
            }

            object->Release();
        }

        if (index == 0) {
            std::wcout << L"  No data returned.\n";
        }

        if (enumerator) enumerator->Release();
    }

private:
    IWbemLocator* locator_ = nullptr;
    IWbemServices* services_ = nullptr;
};
// Initialize COM for WMI usage, handling common initialization errors and setting the security context.
bool InitializeCom(bool& comInitialized) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        std::wcerr << L"Failed to initialize COM: 0x" << std::hex << hr << std::dec << L"\n";
        return false;
    }
    comInitialized = (hr != RPC_E_CHANGED_MODE);

    hr = CoInitializeSecurity(
        nullptr,
        -1,
        nullptr,
        nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE,
        nullptr);

    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        std::wcerr << L"Failed to initialize COM security: 0x" << std::hex << hr << std::dec << L"\n";
        return false;
    }

    return true;
}
// Convert a processor architecture constant to a human-readable string.
std::wstring ProcessorArchitectureText(WORD architecture) {
    switch (architecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: return L"x64";
    case PROCESSOR_ARCHITECTURE_ARM: return L"ARM";
    case PROCESSOR_ARCHITECTURE_ARM64: return L"ARM64";
    case PROCESSOR_ARCHITECTURE_INTEL: return L"x86";
    default: return L"Unknown";
    }
}
// Convert a firmware type constant to a human-readable string.
std::wstring FirmwareTypeText(FIRMWARE_TYPE type) {
    switch (type) {
    case FirmwareTypeBios: return L"BIOS";
    case FirmwareTypeUefi: return L"UEFI";
    case FirmwareTypeMax: return L"Max";
    default: return L"Unknown";
    }
}
// Print memory information using the GlobalMemoryStatusEx WinAPI function.
void PrintMemoryFromWinApi() {
    MEMORYSTATUSEX memory;
    memory.dwLength = sizeof(memory);

    std::wcout << L"\n=== Memory via WinAPI ===\n";
    if (GlobalMemoryStatusEx(&memory)) {
        PrintLine(L"Total physical memory", BytesToGiB(memory.ullTotalPhys));
        PrintLine(L"Available physical memory", BytesToGiB(memory.ullAvailPhys));
        PrintLine(L"Total virtual memory", BytesToGiB(memory.ullTotalVirtual));
        PrintLine(L"Available virtual memory", BytesToGiB(memory.ullAvailVirtual));
        PrintLine(L"Memory load", std::to_wstring(memory.dwMemoryLoad) + L" %");
    } else {
        std::wcerr << L"  GlobalMemoryStatusEx failed.\n";
    }
}
// Print basic environment information using various WinAPI functions.
void PrintBasicEnvironment() {
    SYSTEM_INFO systemInfo;
    GetNativeSystemInfo(&systemInfo);

    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD computerNameSize = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(computerName, &computerNameSize);

    wchar_t userName[256] = {};
    DWORD userNameSize = 256;
    GetUserNameW(userName, &userNameSize);

    wchar_t windowsDirectory[MAX_PATH] = {};
    GetWindowsDirectoryW(windowsDirectory, MAX_PATH);

    wchar_t systemDirectory[MAX_PATH] = {};
    GetSystemDirectoryW(systemDirectory, MAX_PATH);

    FIRMWARE_TYPE firmwareType = FirmwareTypeUnknown;
    GetFirmwareType(&firmwareType);

    std::wcout << L"=== Basic WinAPI Information ===\n";
    PrintLine(L"Computer name", computerName);
    PrintLine(L"User name", userName);
    PrintLine(L"Processor architecture", ProcessorArchitectureText(systemInfo.wProcessorArchitecture));
    PrintLine(L"Logical processors", std::to_wstring(systemInfo.dwNumberOfProcessors));
    PrintLine(L"Memory page size", std::to_wstring(systemInfo.dwPageSize) + L" bytes");
    PrintLine(L"Minimum app address", std::to_wstring(reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress)));
    PrintLine(L"Maximum app address", std::to_wstring(reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress)));
    PrintLine(L"Windows directory", windowsDirectory);
    PrintLine(L"System directory", systemDirectory);
    BOOL isWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &isWow64);
    PrintLine(L"64-bit OS", BoolText(sizeof(void*) == 8 || isWow64));
    PrintLine(L"Firmware type", FirmwareTypeText(firmwareType));
}
// Print a summary of selected environment variables that may be relevant for system information.
void PrintEnvironmentSummary() {
    std::wcout << L"\n=== Environment Variables ===\n";
    PrintLine(L"USERDOMAIN", GetEnvValue(L"USERDOMAIN"));
    PrintLine(L"USERNAME", GetEnvValue(L"USERNAME"));
    PrintLine(L"COMPUTERNAME", GetEnvValue(L"COMPUTERNAME"));
    PrintLine(L"PROCESSOR_IDENTIFIER", GetEnvValue(L"PROCESSOR_IDENTIFIER"));
    PrintLine(L"PROCESSOR_ARCHITECTURE", GetEnvValue(L"PROCESSOR_ARCHITECTURE"));
    PrintLine(L"NUMBER_OF_PROCESSORS", GetEnvValue(L"NUMBER_OF_PROCESSORS"));
    PrintLine(L"TEMP", GetEnvValue(L"TEMP"));
    PrintLine(L"USERPROFILE", GetEnvValue(L"USERPROFILE"));
}
// Run a series of WMI queries against the CIMV2 namespace to gather detailed system information, printing the results with specified labels.
void RunCimv2Queries(WmiConnection& wmi) {
    wmi.QueryAndPrint(L"Operating System",
        L"SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, SerialNumber, RegisteredUser, Organization, WindowsDirectory, SystemDirectory, Locale, CountryCode, CurrentTimeZone, MUILanguages FROM Win32_OperatingSystem",
        {{L"Caption", L"Name"}, {L"Version", L"Version"}, {L"BuildNumber", L"Build"}, {L"OSArchitecture", L"Architecture"}, {L"InstallDate", L"Install date"}, {L"LastBootUpTime", L"Last boot time"}, {L"SerialNumber", L"Serial number"}, {L"RegisteredUser", L"Registered user"}, {L"Organization", L"Organization"}, {L"WindowsDirectory", L"Windows directory"}, {L"SystemDirectory", L"System directory"}, {L"Locale", L"Locale"}, {L"CountryCode", L"Country code"}, {L"CurrentTimeZone", L"Current time zone"}, {L"MUILanguages", L"MUI languages"}});

    wmi.QueryAndPrint(L"Computer System",
        L"SELECT Manufacturer, Model, SystemFamily, SystemSKUNumber, SystemType, Domain, Workgroup, PartOfDomain, TotalPhysicalMemory, NumberOfProcessors, NumberOfLogicalProcessors, UserName, BootupState, HypervisorPresent FROM Win32_ComputerSystem",
        {{L"Manufacturer", L"Manufacturer"}, {L"Model", L"Model"}, {L"SystemFamily", L"System family"}, {L"SystemSKUNumber", L"System SKU"}, {L"SystemType", L"System type"}, {L"Domain", L"Domain"}, {L"Workgroup", L"Workgroup"}, {L"PartOfDomain", L"Part of domain"}, {L"TotalPhysicalMemory", L"Total RAM bytes"}, {L"NumberOfProcessors", L"Physical CPU count"}, {L"NumberOfLogicalProcessors", L"Logical CPU count"}, {L"UserName", L"Logged-in user"}, {L"BootupState", L"Boot state"}, {L"HypervisorPresent", L"Hypervisor present"}});

    wmi.QueryAndPrint(L"CPU",
        L"SELECT Name, Manufacturer, Description, Architecture, Family, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, CurrentClockSpeed, L2CacheSize, L3CacheSize, ProcessorId, SocketDesignation, VirtualizationFirmwareEnabled, SecondLevelAddressTranslationExtensions, VMMonitorModeExtensions FROM Win32_Processor",
        {{L"Name", L"Name"}, {L"Manufacturer", L"Manufacturer"}, {L"Description", L"Description"}, {L"Architecture", L"Architecture"}, {L"Family", L"Family"}, {L"NumberOfCores", L"Cores"}, {L"NumberOfLogicalProcessors", L"Threads"}, {L"MaxClockSpeed", L"Max clock MHz"}, {L"CurrentClockSpeed", L"Current clock MHz"}, {L"L2CacheSize", L"L2 cache KiB"}, {L"L3CacheSize", L"L3 cache KiB"}, {L"ProcessorId", L"Processor ID"}, {L"SocketDesignation", L"Socket"}, {L"VirtualizationFirmwareEnabled", L"Firmware virtualization"}, {L"SecondLevelAddressTranslationExtensions", L"SLAT support"}, {L"VMMonitorModeExtensions", L"VM monitor extensions"}});

    wmi.QueryAndPrint(L"GPU",
        L"SELECT Name, AdapterCompatibility, AdapterRAM, DriverVersion, DriverDate, VideoProcessor, VideoArchitecture, VideoMemoryType, VideoModeDescription, CurrentHorizontalResolution, CurrentVerticalResolution, CurrentRefreshRate, CurrentBitsPerPixel, Status FROM Win32_VideoController",
        {{L"Name", L"Name"}, {L"AdapterCompatibility", L"Manufacturer"}, {L"AdapterRAM", L"VRAM bytes"}, {L"DriverVersion", L"Driver version"}, {L"DriverDate", L"Driver date"}, {L"VideoProcessor", L"Video processor"}, {L"VideoArchitecture", L"Video architecture"}, {L"VideoMemoryType", L"Video memory type"}, {L"VideoModeDescription", L"Video mode"}, {L"CurrentHorizontalResolution", L"Resolution X"}, {L"CurrentVerticalResolution", L"Resolution Y"}, {L"CurrentRefreshRate", L"Refresh rate Hz"}, {L"CurrentBitsPerPixel", L"Bits per pixel"}, {L"Status", L"Status"}});

    wmi.QueryAndPrint(L"Physical Memory Modules",
        L"SELECT BankLabel, DeviceLocator, Manufacturer, PartNumber, SerialNumber, Capacity, Speed, ConfiguredClockSpeed, MemoryType, SMBIOSMemoryType, FormFactor, DataWidth, TotalWidth FROM Win32_PhysicalMemory",
        {{L"BankLabel", L"Bank"}, {L"DeviceLocator", L"Slot"}, {L"Manufacturer", L"Manufacturer"}, {L"PartNumber", L"Part number"}, {L"SerialNumber", L"Serial number"}, {L"Capacity", L"Capacity bytes"}, {L"Speed", L"Speed MHz"}, {L"ConfiguredClockSpeed", L"Configured speed MHz"}, {L"MemoryType", L"Memory type"}, {L"SMBIOSMemoryType", L"SMBIOS memory type"}, {L"FormFactor", L"Form factor"}, {L"DataWidth", L"Data width"}, {L"TotalWidth", L"Total width"}});

    wmi.QueryAndPrint(L"BIOS",
        L"SELECT Manufacturer, Name, Version, SMBIOSBIOSVersion, SMBIOSMajorVersion, SMBIOSMinorVersion, ReleaseDate, SerialNumber, BIOSVersion FROM Win32_BIOS",
        {{L"Manufacturer", L"Manufacturer"}, {L"Name", L"Name"}, {L"Version", L"Version"}, {L"SMBIOSBIOSVersion", L"SMBIOS BIOS version"}, {L"SMBIOSMajorVersion", L"SMBIOS major"}, {L"SMBIOSMinorVersion", L"SMBIOS minor"}, {L"ReleaseDate", L"Release date"}, {L"SerialNumber", L"Serial number"}, {L"BIOSVersion", L"BIOS versions"}});

    wmi.QueryAndPrint(L"Motherboard",
        L"SELECT Manufacturer, Product, Version, SerialNumber, HostingBoard, PoweredOn FROM Win32_BaseBoard",
        {{L"Manufacturer", L"Manufacturer"}, {L"Product", L"Product"}, {L"Version", L"Version"}, {L"SerialNumber", L"Serial number"}, {L"HostingBoard", L"Hosting board"}, {L"PoweredOn", L"Powered on"}});

    wmi.QueryAndPrint(L"Physical Disks",
        L"SELECT Model, Manufacturer, InterfaceType, MediaType, SerialNumber, FirmwareRevision, Size, Partitions, BytesPerSector, SCSIBus, SCSILogicalUnit, SCSIPort, Status FROM Win32_DiskDrive",
        {{L"Model", L"Model"}, {L"Manufacturer", L"Manufacturer"}, {L"InterfaceType", L"Interface"}, {L"MediaType", L"Media type"}, {L"SerialNumber", L"Serial number"}, {L"FirmwareRevision", L"Firmware"}, {L"Size", L"Size bytes"}, {L"Partitions", L"Partitions"}, {L"BytesPerSector", L"Bytes per sector"}, {L"SCSIBus", L"SCSI bus"}, {L"SCSILogicalUnit", L"SCSI logical unit"}, {L"SCSIPort", L"SCSI port"}, {L"Status", L"Status"}});

    wmi.QueryAndPrint(L"Logical Volumes",
        L"SELECT DeviceID, VolumeName, VolumeSerialNumber, FileSystem, Size, FreeSpace, DriveType, ProviderName, Compressed FROM Win32_LogicalDisk",
        {{L"DeviceID", L"Drive"}, {L"VolumeName", L"Volume name"}, {L"VolumeSerialNumber", L"Volume serial"}, {L"FileSystem", L"File system"}, {L"Size", L"Size bytes"}, {L"FreeSpace", L"Free bytes"}, {L"DriveType", L"Drive type"}, {L"ProviderName", L"Network path"}, {L"Compressed", L"Compressed"}});

    wmi.QueryAndPrint(L"Network Adapters",
        L"SELECT Name, Description, MACAddress, Speed, NetConnectionID, NetConnectionStatus, Manufacturer, AdapterType, PhysicalAdapter, PNPDeviceID FROM Win32_NetworkAdapter WHERE PhysicalAdapter=True",
        {{L"Name", L"Name"}, {L"Description", L"Description"}, {L"MACAddress", L"MAC address"}, {L"Speed", L"Speed bit/s"}, {L"NetConnectionID", L"Connection"}, {L"NetConnectionStatus", L"Connection status"}, {L"Manufacturer", L"Manufacturer"}, {L"AdapterType", L"Adapter type"}, {L"PhysicalAdapter", L"Physical adapter"}, {L"PNPDeviceID", L"PNP device ID"}});

    wmi.QueryAndPrint(L"IP Configuration",
        L"SELECT Description, DHCPEnabled, DHCPServer, DNSHostName, DNSDomain, IPAddress, IPSubnet, DefaultIPGateway, DNSServerSearchOrder, MACAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True",
        {{L"Description", L"Adapter"}, {L"DHCPEnabled", L"DHCP enabled"}, {L"DHCPServer", L"DHCP server"}, {L"DNSHostName", L"DNS host name"}, {L"DNSDomain", L"DNS domain"}, {L"IPAddress", L"IP addresses"}, {L"IPSubnet", L"Subnets"}, {L"DefaultIPGateway", L"Gateways"}, {L"DNSServerSearchOrder", L"DNS servers"}, {L"MACAddress", L"MAC address"}});

    wmi.QueryAndPrint(L"Monitors",
        L"SELECT Name, MonitorManufacturer, MonitorType, PixelsPerXLogicalInch, PixelsPerYLogicalInch, ScreenHeight, ScreenWidth FROM Win32_DesktopMonitor",
        {{L"Name", L"Name"}, {L"MonitorManufacturer", L"Manufacturer"}, {L"MonitorType", L"Type"}, {L"PixelsPerXLogicalInch", L"Pixels per X inch"}, {L"PixelsPerYLogicalInch", L"Pixels per Y inch"}, {L"ScreenHeight", L"Screen height"}, {L"ScreenWidth", L"Screen width"}});

    wmi.QueryAndPrint(L"Sound Devices",
        L"SELECT Name, Manufacturer, ProductName, Status, PNPDeviceID FROM Win32_SoundDevice",
        {{L"Name", L"Name"}, {L"Manufacturer", L"Manufacturer"}, {L"ProductName", L"Product name"}, {L"Status", L"Status"}, {L"PNPDeviceID", L"PNP device ID"}});

    wmi.QueryAndPrint(L"USB Controllers",
        L"SELECT Name, Manufacturer, DeviceID, PNPDeviceID, Status FROM Win32_USBController",
        {{L"Name", L"Name"}, {L"Manufacturer", L"Manufacturer"}, {L"DeviceID", L"Device ID"}, {L"PNPDeviceID", L"PNP device ID"}, {L"Status", L"Status"}});

    wmi.QueryAndPrint(L"USB Hubs",
        L"SELECT Name, DeviceID, PNPDeviceID, Status FROM Win32_USBHub",
        {{L"Name", L"Name"}, {L"DeviceID", L"Device ID"}, {L"PNPDeviceID", L"PNP device ID"}, {L"Status", L"Status"}});

    wmi.QueryAndPrint(L"Printers",
        L"SELECT Name, DriverName, PortName, Default, Network, Shared, WorkOffline, PrinterStatus FROM Win32_Printer",
        {{L"Name", L"Name"}, {L"DriverName", L"Driver"}, {L"PortName", L"Port"}, {L"Default", L"Default"}, {L"Network", L"Network"}, {L"Shared", L"Shared"}, {L"WorkOffline", L"Offline"}, {L"PrinterStatus", L"Printer status"}});

    wmi.QueryAndPrint(L"Page File Usage",
        L"SELECT Name, AllocatedBaseSize, CurrentUsage, PeakUsage, TempPageFile FROM Win32_PageFileUsage",
        {{L"Name", L"Name"}, {L"AllocatedBaseSize", L"Allocated MiB"}, {L"CurrentUsage", L"Current usage MiB"}, {L"PeakUsage", L"Peak usage MiB"}, {L"TempPageFile", L"Temporary page file"}});

    wmi.QueryAndPrint(L"Startup Commands",
        L"SELECT Name, Command, Location, User FROM Win32_StartupCommand",
        {{L"Name", L"Name"}, {L"Command", L"Command"}, {L"Location", L"Location"}, {L"User", L"User"}});

    wmi.QueryAndPrint(L"Battery",
        L"SELECT Name, EstimatedChargeRemaining, BatteryStatus, EstimatedRunTime, Chemistry FROM Win32_Battery",
        {{L"Name", L"Name"}, {L"EstimatedChargeRemaining", L"Charge remaining %"}, {L"BatteryStatus", L"Battery status"}, {L"EstimatedRunTime", L"Estimated runtime minutes"}, {L"Chemistry", L"Chemistry"}});
}
// The main function initializes the environment, runs the information gathering, and optionally saves the report to a file.
int wmain() {
    SetConsoleOutputCP(CP_UTF8);
    std::locale::global(std::locale(""));
    std::wcout.imbue(std::locale());
    std::wcin.imbue(std::locale());

    std::wostringstream report;
    TeeWBuffer teeBuffer(std::wcout.rdbuf(), report.rdbuf());
    std::wstreambuf* originalCout = std::wcout.rdbuf(&teeBuffer);

    PrintBasicEnvironment();
    PrintMemoryFromWinApi();
    PrintEnvironmentSummary();

    bool comInitialized = false;
    if (!InitializeCom(comInitialized)) {
        std::wcout.rdbuf(originalCout);
        std::wcerr << L"\nUnable to initialize COM/WMI.\n";
        return 1;
    }

    {
        WmiConnection wmi;
        if (!wmi.Connect()) {
            std::wcout.rdbuf(originalCout);
            if (comInitialized) CoUninitialize();
            std::wcerr << L"\nUnable to query WMI. Run the program from a terminal with sufficient permissions.\n";
            return 1;
        }

        RunCimv2Queries(wmi);
		// Attempt to query additional namespaces for security products, TPM, and thermal zones, handling cases where access is denied or namespaces are unavailable.
        WmiConnection security;
        if (security.Connect(L"ROOT\\SecurityCenter2", false)) {
            security.QueryAndPrint(L"Security Products",
                L"SELECT displayName, pathToSignedProductExe, pathToSignedReportingExe, productState, timestamp FROM AntiVirusProduct",
                {{L"displayName", L"Display name"}, {L"pathToSignedProductExe", L"Product executable"}, {L"pathToSignedReportingExe", L"Reporting executable"}, {L"productState", L"Product state"}, {L"timestamp", L"Timestamp"}});
        } else {
            std::wcout << L"\n=== Security Products ===\n  SecurityCenter2 namespace is not available or access was denied.\n";
        }
		// The TPM namespace may not be present on all systems, and access may be restricted, so we handle that gracefully.
        WmiConnection tpm;
        if (tpm.Connect(L"ROOT\\CIMV2\\Security\\MicrosoftTpm", false)) {
            tpm.QueryAndPrint(L"TPM",
                L"SELECT IsActivated_InitialValue, IsEnabled_InitialValue, IsOwned_InitialValue, ManufacturerId, ManufacturerIdTxt, ManufacturerVersion, SpecVersion FROM Win32_Tpm",
                {{L"IsActivated_InitialValue", L"Activated"}, {L"IsEnabled_InitialValue", L"Enabled"}, {L"IsOwned_InitialValue", L"Owned"}, {L"ManufacturerId", L"Manufacturer ID"}, {L"ManufacturerIdTxt", L"Manufacturer text"}, {L"ManufacturerVersion", L"Manufacturer version"}, {L"SpecVersion", L"Spec version"}});
        } else {
            std::wcout << L"\n=== TPM ===\n  TPM namespace is not available or access was denied.\n";
        }
		// Thermal zone information may also be restricted or unavailable on some systems, so we handle that case as well.
        WmiConnection thermal;
        if (thermal.Connect(L"ROOT\\WMI", false)) {
            thermal.QueryAndPrint(L"Thermal Zones",
                L"SELECT InstanceName, CurrentTemperature, CriticalTripPoint FROM MSAcpi_ThermalZoneTemperature",
                {{L"InstanceName", L"Instance"}, {L"CurrentTemperature", L"Current temperature"}, {L"CriticalTripPoint", L"Critical trip point"}});
        } else {
            std::wcout << L"\n=== Thermal Zones ===\n  ROOT\\WMI namespace is not available or access was denied.\n";
        }
    }

    std::wcout << L"\nProcessing complete.\n";
    std::wcout.rdbuf(originalCout);
	// Ask the user if they want to save the report to a file, and if so, generate a file name and save the contents of the report string.
    std::wcout << L"\nDo you want to save this information to a text file? (Y/N): ";
    wchar_t answer = L'N';
    std::wcin >> answer;

    if (answer == L'Y' || answer == L'y' || answer == L'O' || answer == L'o') {
        const std::wstring fileName = MakeReportFileName();
        if (SaveReportToFile(fileName, report.str())) {
            std::wcout << L"Report saved: " << fileName << L"\n";
        } else {
            std::wcerr << L"Error: unable to save the report.\n";
        }
    } else {
        std::wcout << L"Report not saved.\n";
    }

    if (comInitialized) CoUninitialize();
    return 0;
}
