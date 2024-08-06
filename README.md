# CopyFeatureProfile


## Objective

Copy Feature Profile which is not avaiable on 20.12-20.14 


## Requirements

To use this code you will need:

- Python 3.7+
- vManage user login details. (User should have privilege level to edit the config groups)
- Feature profile that needs to be copied


## Install and Setup

Clone the code to local machine.

```bash
git clone https://github.com/shreyas23reddy/CopyFeatureProfile
```
```bash
cd CopyFeatureProfile
```

## Setup Python Virtual Environment (requires Python 3.7+)

```bash
python3.7 -m venv venv
source venv/bin/activate
```
```bash
pip3 install -r requirements.txt
```

## Execution: 

Enter your ip_address :- vmanage-xxxxxx.viptela.net
Enter your port :- 8443
Enter your admin_username :- cisco
Enter your admin_password :- **********
Enter the Feature Profile Name that needs to be replicated :- Test2_WAN
Enter the new feature profile Name :- Test2_WAN_copy

 Successfuly copied Test2_WAN feature profile and created Test2_WAN_copy
