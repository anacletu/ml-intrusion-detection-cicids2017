# Network Packet Capture Files

This directory is intended to contain packet capture (PCAP) files for testing the NIDS prototypes. Due to GitHub storage limitations, the actual PCAP files are not included in this repository.

## How to Obtain the PCAP Files

### CICIDS2017 Dataset

The CICIDS2017 dataset contains network traffic captures including normal activity and various attacks such as DoS, DDoS, brute force, and web attacks.

1. Visit the Canadian Institute for Cybersecurity website: https://www.unb.ca/cic/datasets/ids-2017.html
2. Follow the instructions to request access to the dataset
3. Download the PCAP files and place them in this directory

### UNSW-NB15 Dataset

The UNSW-NB15 dataset contains a hybrid of real modern normal activities and synthetic contemporary attack behaviors.

1. Visit the UNSW-NB15 dataset page: https://research.unsw.edu.au/projects/unsw-nb15-dataset
2. Download the raw network packet captures
3. Place the downloaded PCAP files in this directory

## Using the PCAP Files with the NIDS

After downloading the PCAP files:

1. Place them in this directory
2. Use the test scripts in the `prototype` directory to analyze the files
3. For testing with specific PCAP files, use:

```Python
prototype/nids_prototype_xgboost.py --pcap path/to/pcapfile.pcap
```

Note: Some of these PCAP files can be quite large (several GB). Ensure you have sufficient disk space before downloading.
