## Restart Alice
```
systemctl restart alice
```

## Alice Directory
```
/root/cc-alice
```

## Alice Deployment
```
Primary Alice (WA1): 10.88.10.202
Secondary Alice (UC1): 10.124.15.156
```

## Alice Logs
```
/root/cc-alice/alice.log
```

## Troubleshooting Alice
- SSH to WA1 NOC Box
To restart Primary Alice:
```
ssh root@10.88.10.202
systemctl status alice 
systemctl restart alice
systemctl status alice
```

- If Primary Alice is unresponsive, login to Secondary Alice (10.124.15.156)
```
ssh root@10.124.15.156
systemctl start alice
```

