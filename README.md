# Logging NAT Translations on PF firewalls

PFNATTRACK is a tool that can be used to keep track and logging of NAT translations in PF (Packet Filter) firewalls. The logging capability for Network Address Translations is an important step for Computer Security Incident Handling. Usually, the security incidents notifications reported to your institution came only with public IP address, date/time and source port, making it difficult to find the internal machine related to the issue.

Using PFNATTRACK you will get logs such as:
```
2020-09-27 20:44:56 proto=6 osrc=10.10.0.100:54191 odst=172.217.21.202:443 tsrc=10.0.0.248:50444 tdst=172.217.21.202:443 duration=90
2020-09-27 20:44:56 proto=6 osrc=10.10.0.100:35183 odst=172.217.21.202:443 tsrc=10.0.0.248:10176 tdst=172.217.21.202:443 duration=90
2020-09-27 20:44:56 proto=6 osrc=10.10.0.100:52096 odst=172.217.21.202:443 tsrc=10.0.0.248:30599 tdst=172.217.21.202:443 duration=90
```

## Compiling

Use the given Makefile to compile :


```
make

```

## Running

Just launch PFNATTRACK passing command line option "-d" indicating the DIR where save the files (or without option to print on STDOUT) by running:
```
./pf_nattrack [-d PathToExistingOutDir]
```

## Issues and Contributing

Feel free to make a pull request for fixes and improvements!
