# Debugging

## VS Code C Debugger (gdb)

To enable debugging, compile the application with the `-g` flag.In the launch configuration (`launch.json`), define the program's executable and the arguments.

If the application requires root privileges, e.g., because it uses the system's hugepages, the gdb debugger has to be executed as root. However, the VS Code launch configuration (`launch.json`) does not have the option to start the C debugging process as root. Therefore, create a new script which starts the debugger as root and use this to execute the debugger (here gdb).

E.g., `sgdb.sh`:
```
sudo /usr/bin/gdb "$@"
```
Note: The script has to be executable and passwordless sudo might be required.

Modify the launch configuration to call the script, instead of the default debugger.

The configuration file (`launch.json`) could look like the following:
```
"version": "0.2.0",
"configurations": [
    {
        "name": "Debug LF",
        "type": "cppdbg",
        "request": "launch",
        "program": "${workspaceFolder}/build/src/lf",
        "args": ["--log-level", "lf:debug", "-a", "0000:88:00.1", "--", "-p", "0x1", "--portmap", "(0,0)"],
        "stopAtEntry": false,
        "cwd": "${workspaceFolder}",
        "externalConsole": false,
        "MIMode": "gdb",
        "miDebuggerPath": "${workspaceFolder}/sgdp.sh",
        "setupCommands": [
            {
                "description": "Enable pretty-printing for gdb",
                "text": "-enable-pretty-printing",
                "ignoreFailures": true,
            },
            {
                "description":  "Set Disassembly Flavor to Intel",
                "text": "-gdb-set disassembly-flavor intel",
                "ignoreFailures": true
            },
        ]
    }
]
```