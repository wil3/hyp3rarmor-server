# Hyp3rArmor-Server 

Hyp3rArmor-Server virtually eliminates a web servers attack surface to
unauthorized clients. Please refer to the [project parent](https://github.com/wil3/hyp3rarmor) for more details and supporting software.


## Warning

This code is in active development. It is not recommended to use in production
at this time.



# Dependencies

Install the following Ubuntu packages,

```
sudo apt-get install python python-dev python-pip build-essential libssl-dev libffi-dev libpcap-dev libpq-dev
```

Break down of dependencies:

* Common: python python-dev python-pip
* Required by Python library cryptography.io: build-essential libssl-dev libffi-dev
* Required by Python library pcapy: libpcap-dev libpq-dev

Install the Python dependencies,

```
sudo pip install -r requirements.txt
```


# Configuration
Applying Hyp3rArmor will remove the servers visible footprint. You must have a
method for hiding your SSH service. The firewall configuration file `conf/firewall.sh` can be configured to specify an IP address to whitelist, or alternatively install a [port knocking daemon](http://portknocking.org/).

The Hyp3rArmor configuration  file is located in `conf/hyp3rarmor.yaml`.
For  configuration help please read our technical report [Hyp3rArmor
Reducing Web Application Exposure to Automated Attacks](http://www.cs.bu.edu/techreports/pdf/2016-010-hyp3rarmor.pdf)



Note: If running on a virtual-machine you must install an NTP client such as `ntp` on
Ubuntu to handle time drift.

# Running 

Run the Hyp3rArmor daemon,

```
sudo python hyp3rarmor.py
```

Optionally an Upstart configuration file is located at `hyp3rarmor.conf`. Be
sure to change the directory to point to the location where the Hyp3rArmor
server resides. 


If exporting the token to the visible server an `rsync` utility script is located
in `utils/export_token.sh`.
