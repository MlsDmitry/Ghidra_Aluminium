# Ghidra Aluminium
Ghidra plugin for complete integration with community's / IDA's Lumina server

## Get license info to communicate with official IDA's server
1. In $IDA_DIR/cfg/ida.cfg edit: 
    <br />
    `LUMINA_HOST = "localhost";`,
    <br /> 
    `LUMINA_PORT = 1337`,
    <br />
    `LUMINA_TLS = NO`
2. Execute method getIdaLicenseInfo of class Communication
3. Ctrl+c & ctrl+v to SERVER_STUFF in $PLUGIN_DIR/config.py 

#### *based on https://github.com/synacktiv/lumina_server*
