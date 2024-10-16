# EtwFileMon
ETW based file monitoring service

## Overview

This project consists of two executables, `EtwService.exe` and `EtwFileMonitor.exe`, designed to work together for monitoring file activities in a specified directory. 

### Files:
- **EtwService.exe**: Windows service that manages the file monitoring operations.
- **EtwFileMonitor.exe**: Monitors file activities in the configured directory.

### Configuration:
- **Config.txt**: Specifies the directory to monitor. The format is as follows:

    ```
    directory=C:\etwTestFolder\
    ```

## Setup Instructions

### Step 1: Prepare Executables and Configuration
1. Place `EtwService.exe`, `EtwFileMonitor.exe`, and `Config.txt` in the same directory.
2. Edit `Config.txt` to specify the directory you want to monitor for file activities. Example content:

    ```
    directory=C:\etwTestFolder\
    ```

### Step 2: Install the Service
To install and start the service, use the following command in the directory containing the executables:

```bash
EtwService.exe --install

Once installed, the service will be listed in Services.msc. You can manage the service from there as well.

### Step 3: Uninstall the Service
To uninstall the service, use the following command:

EtwService.exe --uninstall

### Logs
EtwFileMonitor.log: The file event log will be created in the same directory as EtwFileMonitor.exe. This log will contain the details of file activities occurring in the monitored directory.

### Notes
The service will monitor file activities in the directory specified in Config.txt.
Make sure the configuration file and executables are kept in the same directory for proper functioning.

