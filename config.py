SERVER_STUFF = {
    "servers": [
        #-------Address-------  -Port-  -allowToPushThere- -anonMode- -sendLicense-  -useTLS- -pathToTLSCert-
        # ["lumina.hex-rays.com",    443,             False,      True,         True,    "OFF", ""],
        [      "lumen.abda.nl",   1235,             False,      True,        False,    "OFF", ""]
    ],

    #
    # anonMode - send to server random: md5 of input file, absolute file path of current idb, absolute file path of input file and machine name
    #

    # Use getIdaLicenseInfo to sniff and define the constants. It's only for connecting to lumina.hex-rays.com
    "license": b"",
    "id": 0,
    "watermark": 0
}