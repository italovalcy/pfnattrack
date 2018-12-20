# Logging NAT Translations on PF firewalls

PFNATTRACK is a tool that can be used to keep track and logging of NAT translations in PF (Packet Filter) firewalls. The logging capability for Network Address Translations is an important step for Computer Security Incident Handling. Usually, the security incidents notifications reported to your institution came only with public IP address, date/time and source port, making it difficult to find the internal machine related to the issue.

Using PFNATTRACK you will get logs such as:
```
2016-06-19,21:44:34 proto=6 osrc=192.168.100.105:51496 tsrc=192.168.25.4:2474 odst=192.168.25.7:22 tdst=192.168.25.7:22 duration=117
2016-06-19,22:07:05 proto=17 osrc=192.168.100.105:37205 tsrc=192.168.25.4:22834 odst=8.8.8.8:53 tdst=8.8.8.8:53 duration=30
```

## Compiling

```
cc -o pf_nattrack *.c
```

## Running

Just launch PFNATTRACK by running:
```
./pf_nattrack
```

## Issues and Contributing

Feel free to make a pull request for fixes and improvements!
