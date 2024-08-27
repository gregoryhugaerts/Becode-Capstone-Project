## Command and Control Server creation and traffic detection

- Comptenece: **Generation and Detection**</br>
- Duration: **2 weeks** </br>
- Challenge Type: **Team**

## Objective

Generating and Detecting Command and Control (C2) traffic

## Tasks

1. Deploy the C2 Server.

- Set up a C2 server using Metasploit.
- Host the C2 server on a VM on a BeCode PC.

2. Simulate Infected Hosts.

- Deploy a few internal VMs configured to simulate compromised endpoints.
- Install lightweight malware simulation tools like Caldera or Red Team Automation (RTA) to simulate beaconing behavior back to the C2 server.

3. Threat Hunting

- Ensure that Splunk is set up to collect and analyze logs from various sources including firewalls, DNS servers, web proxies, endpoint detection and response (EDR) solutions, and the C2 server.
- Integrate <https://abuse.ch/> feeds as described earlier to enhance threat detection.
