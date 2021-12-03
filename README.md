# Check TrueNAS - Extended Play
This is a TrueNAS/FreeNAS Nagios check script. Checks for Alerts, Pool health, Replication errors, etc.

This is an updated version of `check_truenas.py`, written by Goran Tornqvist, and originally found here:

https://exchange.nagios.org/directory/Plugins/Hardware/Storage-Systems/SAN-and-NAS/Check-TrueNAS-Health-2FReplication/details
```
Checks a TrueNAS/FreeNAS server using the 2.0 API. Version 1.2

optional arguments:
  -h, --help            show this help message and exit
  -H HOSTNAME, --hostname HOSTNAME
                        Hostname or IP address
  -u USER, --user USER  Normally only root works
  -p PASSWD, --passwd PASSWD
                        Password for Username provided by --user, OR if --user is not supplied, --passwd must be an API key
  -t TYPE, --type TYPE  Type of check, either alerts, zpool, or repl
  -pn ZPOOLNAME, --zpoolname ZPOOLNAME
                        For check type zpool, the name of zpool to check.
                        Optional; defaults to all zpools.
  -ns, --no-ssl         Disable SSL (use HTTP); default is to use SSL (use
                        HTTPS)
  -nv, --no-verify-cert
                        Do not verify the server SSL cert; default is to
                        verify the SSL cert
  -ig, --ignore-dismissed-alerts
                        Ignore alerts that have already been dismissed in
                        FreeNas/TrueNAS; default is to treat them as relevant
  -d, --debug           Display debugging information; run script this way and
                        record result when asking for help.
```
# Requirements

- python3-urllib3  
- python3-requests

# Usage Examples:

#### Check for alerts. This may be all the average user needs to set up. TrueNAS/FreeNas alerts about nearly all significant events here.

#### Alerts normal operation - username/password authentication
```
check_truenas_extended_play.py -H apollo.yourdomain.local -u root -p RootPassy --type alerts -nv
OK - No problem alerts
```

#### Alerts normal operation - API Key authentication
```
check_truenas_extended_play.py -H apollo.yourdomain.local -p 1-weuiK4YY7OUduhpzKISIJJIDIJSJ4YgMwvea3dEhf3ITmoRRYZ3HBkDr2s1KZ1ft7M --type alerts -nv
OK - No problem alerts
```

#### Alerts sample error condition
```
check_truenas_extended_play.py -H sicknas.yourdomain.local -u root -p RootPa$$worD -type alerts -nv -ns
CRITICAL - (C) Space usage for pool "BigMediaThree" is 85%. Optimal pool performance requires
used space remain below 80%. - (W) New feature flags are available for volume BigMediaToo. Refer
to the "Upgrading a ZFS Pool" subsection in the User Guide "Installing and Upgrading" chapter
and "Upgrading" section for more instructions. - (W) New feature flags are available for volume 
BigMediaThree. Refer to the "Upgrading a ZFS Pool" subsection in the User Guide "Installing and Upgrading" 
chapter and "Upgrading" section for more instructions.
```

## Check Zpool health

#### Check all Zpools
```
check_truenas_extended_play.py -H apollo.yourdomain.local -u root -p RootPassy --type zpool -nv
OK - No problem Zpools. Zpools examined:  ApolloZpoolOne ApolloZPoolEleven
```

#### Check a specifically named Zpool, ignoring any others
```
check_truenas_extended_play.py -H apollo.yourdomain.local -u root -p RootPassy --type zpool -nv --zpoolname ApolloZPoolEleven
OK - No problem Zpools. Zpools examined:  ApolloZPoolEleven
```

#### Example of what happens if Zpool is not present
```
check_truenas_extended_play.py -H apollo.yourdomain.local -u root -p RootPassy --type zpool -nv --zpoolname PoolNameWhichIsNotActuallyThere
CRITICAL - No Zpools found matching PoolNameWhichIsNotActuallyThere out of 2 pools (ApolloZpoolOne ApolloZPoolEleven)
```
## Check replication health
```
check_truenas_extended_play.py -H apollo.yourdomain.local -u root -p RootPassy --type repl -nv
OK - No replication errors. Replications examined:  ApolloDatasetReplications: FINISHED
```

# Version History

December 3, 2021 - Version 1.2 - Added API Key authentication. Thanks to Folke Ashberg.


# Feedback Welcome
If you have a suggestion or encounter a problem, I encourage users to get in touch. I've found half-baked Nagios plugins to be a chore to deal with, and I'd like this not to be one of them.
