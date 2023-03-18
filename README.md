# CVE-2022-22963 Reverse Shell Exploit

This is a Python script that exploits CVE-2022-22963, a remote code execution vulnerability in Spring Cloud Function that allows attackers to execute arbitrary code on a vulnerable server. The exploit uses the vulnerable `/functionRouter` endpoint to execute a command on the target server.

## Usage

To use this exploit, simply run the script with the `-u` option to specify the URL of the vulnerable server. The script will check if the server is vulnerable and prompt the user if they want to attempt to take a reverse shell. If the user chooses to proceed, the script will open a netcat listener and attempt to execute the specified command on the target server.
