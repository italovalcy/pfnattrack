# Logging NAT Translations on PF firewalls

PFNATTRACK is a tool that can be used to keep track and logging of NAT translations in PF (Packet Filter) firewalls. The logging capability for Network Address Translations is an important step for Computer Security Incident Handling. Usually, the security incidents notifications reported to your institution came only with public IP address, date/time and source port, making it difficult to find the internal machine related to the issue.

Using PFNATTRACK you will get logs such as:
```
2020-10-04 17:05:30 UTC tcp osrc=10.10.0.100:42425 (7c:0b:c6:xx:yy:zz) odst=172.217.21.202:443 tsrc=10.0.0.248:54592 tdst=172.217.21.202:443 duration=90
2020-10-04 17:05:30 UTC udp osrc=10.10.0.1:123 (00:1b:21:xx:yy:zz) odst=195.24.76.190:123 tsrc=10.0.0.248:9689 tdst=195.24.76.190:123 duration=34
2020-10-04 17:06:00 UTC tcp osrc=10.10.0.100:34461 (7c:0b:c6:xx:yy:zz) odst=172.217.21.202:443 tsrc=10.0.0.248:49865 tdst=172.217.21.202:443 duration=90
2020-10-04 17:06:15 UTC tcp osrc=10.10.0.100:38741 (7c:0b:c6:xx:yy:zz) odst=172.217.21.202:443 tsrc=10.0.0.248:4535 tdst=172.217.21.202:443 duration=90
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
