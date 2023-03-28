
# Nmap API

Uses python3.10, Debian, python-Nmap, and flask framework to create a Nmap API that can do scans with a good speed online and is easy to deploy.

This is a implementation for our college PCL project which is still under development and constantly updating.


## API Reference

#### Get all items

```
  GET /api/p1/{username}:{password}/{target}
  GET /api/p2/{username}:{password}/{target}
  GET /api/p3/{username}:{password}/{target}
  GET /api/p4/{username}:{password}/{target}
  GET /api/p5/{username}:{password}/{target}
  GET /api/gpt/{username}:{password}/{target}
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `username` | `string` | **Required**. username of the current user |
| `password`| `string`|**Required**. current user password|
| `target`| `string`| **Required**. The target Hostname and IP|

#### Get item

```
  GET /api/p1/
  GET /api/p2/
  GET /api/p3/
  GET /api/p4/
  GET /api/p5/
```

| Parameter | Return data     | Description | Nmap Command |
| :-------- | :------- | :-------------------------------- | :---------|
| `p1`      | `json` | Effective  Scan | `-Pn -sV -T4 -O -F`|
| `p2`      | `json` | Simple  Scan | `-Pn -T4 -A -v`|
| `p3`      | `json` | Low Power  Scan | `-Pn -sS -sU -T4 -A -v`|
| `p4`      | `json` | Partial Intense  Scan | `-Pn -p- -T4 -A -v`|
| `p5`      | `json` | Complete Intense  Scan | `-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln`|


#### Auth and User management

```
  POST /adduser/{admin-username}:{admin-passwd}/{id}/{username}/{passwd}
  POST /deluser/{admin-username}:{admin-passwd}/{t-username}/{t-userpass}
  POST /altusername/{admin-username}:{admin-passwd}/{t-user-id}/{new-t-username}
  POST /altuserid/{admin-username}:{admin-passwd}/{new-t-user-id}/{t-username}
  POST /altpassword/{admin-username}:{admin-passwd}/{t-username}/{new-t-userpass}
```
| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
|`admin-username`|`String`|Admin username|
|`admin-passwd`|`String`|Admin password|
|`id`|`String`|Id for newly added user|
|`username`|`String`|Username of the newly added user|
|`passwd`|`String`|Password of the newly added user|
|`t-username`|`String`|Target username|
|`t-user-id`|`String`|Target userID|
|`t-userpass`|`String`|Target users password|
|`new-t-username`|`String`|New username for the target|
|`new-t-user-id`|`String`|New userID for the target|
|`new-t-userpass`|`String`|New password for the target|

**DEFAULT** **CREDENTIALS**

```ADMINISTRATOR : zAp6_oO~t428)@,```

# GPT Section
The profile is the type of scan that will be executed by the nmap subprocess. The Ip or target will be provided via argparse. At first the custom nmap scan is run which has all the curcial arguments for the scan to continue. nextly the scan data is extracted from the huge pile of data which has been driven by nmap. the "scan" object has a list of sub data under "tcp" each labled according to the ports opened. once the data is extracted the data is sent to openai API davenci model via a prompt. the prompt specifically asks for an JSON output and the data also to be used in a certain manner. 

The entire structure of request that has to be sent to the openai API is designed in the completion section of the Program.
```python
def profile(ip):
    nm.scan('{}'.format(ip), arguments='-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln')
    json_data = nm.analyse_nmap_xml_scan()
    analize = json_data["scan"]
    # Prompt about what the quary is all about
    prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(analize)
    # A structure for the request
    completion = openai.Completion.create(
        engine=model_engine,
        prompt=prompt,
        max_tokens=1024,
        n=1,
        stop=None,
    )
    response = completion.choices[0].text
    return response
```
### Output

```json
{
    "vulnerabilities": [
        {
            "name": "Port 135 Open",
            "type": "network",
            "severity": "low",
            "description": "TCP port 135 is open, which suggests that Microsoft Windows RPC might be running on this system and could potentially be vulnerable to exploitation."
        },
        {
            "name": "Port 445 Open",
            "type": "network",
            "severity": "low",
            "description": "TCP port 445 is open, which suggests that Microsoft Windows File Share might be running on this system and could potentially be vulnerable to exploitation."
        },
        {
            "name": "Port 902 Open",
            "type": "network",
            "severity": "low",
            "description": "TCP port 902 is open, which suggests that VMware Authentication Daemon might be running on this system and could potentially be vulnerable to exploitation."
        },
        {
            "name": "Port 912 Open",
            "type": "network",
            "severity": "low",
            "description": "TCP port 912 is open, which suggests that VMware Authentication Daemon might be running on this system and could potentially be vulnerable to exploitation."
        },
        {
            "name": "Port 20000 Open",
            "type": "network",
            "severity": "low",
            "description": "TCP port 20000 is open, which suggests that the system could potentially be vulnerable to exploitation."
        },
        {
            "name": "Clock Skew Detected",
            "type": "system",
            "severity": "low",
            "description": "A clock skew of -1 second has been detected, which may indicate an incorrect system configuration or an attack on the system clock."
        },
        {
            "name": "Outdated OS Version Detected",
            "type": "system",
            "severity": "medium",
            "description": "Microsoft Windows 10 Version 1607 is detected, which is no longer supported and is known to contain vulnerabilities."
        }
    ]
}
```
