# Check TrueNAS - Extended Play
This is a TrueNAS/FreeNAS Nagios check script. Checks for Alerts, Pool health, Pool capacity, Replication errors, TrueNAS software updates, etc.

This is an updated version of `check_truenas.py`, written by Goran Tornqvist, and originally found here:

https://exchange.nagios.org/directory/Plugins/Hardware/Storage-Systems/SAN-and-NAS/Check-TrueNAS-Health-2FReplication/details
```
Checks a TrueNAS/FreeNAS server using the 2.0 API. Version 1.4

optional arguments:
  -h, --help            show this help message and exit
  -H HOSTNAME, --hostname HOSTNAME
                        Hostname or IP address
  -u USER, --user USER  Username, only root works, if not specified: use API Key
  -p PASSWD, --passwd PASSWD
                        Password or API Key
  -t TYPE, --type TYPE  Type of check, either alerts, zpool, zpool_capacity, repl, or update
  -pn ZPOOLNAME, --zpoolname ZPOOLNAME
                        For check type zpool, the name of zpool to check. Optional; defaults to all zpools.
  -ns, --no-ssl         Disable SSL (use HTTP); default is to use SSL (use HTTPS)
  -nv, --no-verify-cert
                        Do not verify the server SSL cert; default is to verify the SSL cert
  -ig, --ignore-dismissed-alerts
                        Ignore alerts that have already been dismissed in FreeNas/TrueNAS; default is to treat them as
                        relevant
  -d, --debug           Display debugging information; run script this way and record result when asking for help.
  -zw ZPOOL_WARN, --zpool-warn ZPOOL_WARN
                        ZPool warning storage capacity free threshold. Give a percent value in the range 1-100,
                        defaults to 80%. Used with zpool_capacity check.
  -zc ZPOOL_CRITICAL, --zpool-critical ZPOOL_CRITICAL
                        ZPool critical storage capacity free threshold. Give a percent value in the range 1-100,
                        defaults to 90%. Used with zpool_capacity check.
  -zp, --zpool-perfdata
                        Add Zpool capacity perf data to output. Used with zpool_capacity check.
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

## Check Zpool capacity

#### Check all zpools for capacity issues
```
check_truenas_extended_play.py -H apollo.yourdomain.local -t zpool_capacity -p 1-weuiK4YY7OUdukdiejsijeiYFe4YgMwvea3dEhf3ITmoRRYZ3HBkDr2s1KZ1ft7M -nv 
OK - No Zpool capacity issues. ZPools examined: ApolloZpoolOne (75.8% used) ApolloZPoolEleven (64.0% used) Root level datasets examined: ApolloZpoolOne ApolloZPoolEleven
```
Note that the default warning level (80%) and default critical level (90%) will be used here.

#### Check specific zpool for capacity issues
```
check_truenas_extended_play.py -H apollo.yourdomain.local -t zpool_capacity -pn ApolloZpoolOne -p 1-weuiK4YY7OUdukdiejsijeiYFe4YgMwvea3dEhf3ITmoRRYZ3HBkDr2s1KZ1ft7M -nv 
OK - No Zpool capacity issues. ZPools examined: ApolloZpoolOne (75.8% used) Root level datasets examined: ApolloZpoolOne
```

#### Check all zpools with custom warning level
```
check_truenas_extended_play.py -H apollo.yourdomain.local -t zpool_capacity -zw 30 -p 1-weuiK4YY7OUdukdiejsijeiYFe4YgMwvea3dEhf3ITmoRRYZ3HBkDr2s1KZ1ft7M -nv 
WARNING - Pool ApolloZpoolOne usage 75.8% exceeds warning value of 30%- Pool ApolloZPoolEleven usage 64.0% exceeds warning value of 30%
```

#### Check all zpools with custom error level
```
check_truenas_extended_play.py -H apollo.yourdomain.local -t zpool_capacity -zc 40 -p 1-weuiK4YY7OUdukdiejsijeiYFe4YgMwvea3dEhf3ITmoRRYZ3HBkDr2s1KZ1ft7M -nv 
CRITICAL - Pool ApolloZpoolOne usage 75.8% exceeds warning value of 40%- Pool ApolloZPoolEleven usage 64.0% exceeds critical value of 40%
```

#### Check specific zpool for capacity issues, adding on perf data as well
```
check_truenas_extended_play.py -H apollo.yourdomain.local -t zpool_capacity -pn ApolloZpoolOne -zp -p 1-weuiK4YY7OUdukdiejsijeiYFe4YgMwvea3dEhf3ITmoRRYZ3HBkDr2s1KZ1ft7M -nv 
OK - No Zpool capacity issues. ZPools examined: ApolloZpoolOne (75.8% used) Root level datasets examined: ApolloZpoolOne| ApolloZpoolOne=294202.30MB;310479.52;155239.76;0;388099.40
```

## Check replication health
```
check_truenas_extended_play.py -H apollo.yourdomain.local -u root -p RootPassy --type repl -nv
OK - No replication errors. Replications examined:  ApolloDatasetReplications: FINISHED
```
## Check for TrueNAS updates - no updates available
```
check_truenas_extended_play.py -H apollo.yourdomain.local --type update -p 1-weuiK4YY7OUduhpzKISIJJIDIJSJ4YgMwvea3dEhf3ITmoRRYZ3HBkDr2s1KZ1ft7M -nv
OK - Update Status: UNAVAILABLE (no update available)
```
'UNAVAILABLE' is the normal update status, and does not indicate a problem.

## Check for TrueNAS updates - possible updates available
```
check_truenas_extended_play.py -H apollo.yourdomain.local --type update -p 1-weuiK4YY7OUduhpzKISIJJIDIJSJ4YgMwvea3dEhf3ITmoRRYZ3HBkDr2s1KZ1ft7M -nv
WARNING - Update Status: AVAILABLE (an update is available). Update may be required. Go to TrueNAS Dashboard -> System -> Update to check for newer version.
```

All update issues are merely warnings, and not critical errors.

# Version History

*December 3, 2021 - Version 1.2* 

Added API Key authentication. Thanks to Folke Ashberg.

*December 4, 2021 - Version 1.3* 

Added update check, by request of @madtempest.

*December 5, 2021 - Version 1.4*

By popular demand, ZPool capacity checking added. Thanks to both Folke Ashberg and @Cosmits. Each made an independent pull request with a suggested implementation of this feature,  demonstrating it was sorely needed. It has been a bit involved to implement correctly, so if anyone sees free/used values for their ZPools that don't seem right, please let us know.

# Feedback Welcome
If you have a suggestion or encounter a problem, I encourage users to get in touch. I've found half-baked Nagios plugins to be a chore to deal with, and I'd like this not to be one of them.
