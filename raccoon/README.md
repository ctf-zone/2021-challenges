# Raccoon

## Description

Network traffic dump.pcap of a service with strange implementation was captured.
It would be good to examine it.

## Start

```sh
docker-compose up
```

The service will be available on 127.0.0.1:8444.


## Solver

```sh
# Collect good values (will be saved in values.txt)
python3 solver/1_collect.py

# Get possible values of g^ab (will be saved in possible.txt)
sage solver/2_solve.py

# Decrypt data from dump using possible g^ab values
python3 solver/3_decrypt.py
```
