# Ghidra Aluminium
Ghidra plugin for complete integration with community's / IDA's Lumina server

***
## Get license info to communicate with official IDA's server
1. Edit $IDA_DIR/cfg/ida.cfg
    ```
    LUMINA_HOST = "localhost";
    LUMINA_PORT = 6379
    LUMINA_TLS = NO
    ```
2. Execute method getIdaLicenseInfo of class Communication
3. Ctrl+c & ctrl+v to SERVER_STUFF in $PLUGIN_DIR/core/lumina_structs.py 

***
### based on https://github.com/synacktiv/lumina_server
