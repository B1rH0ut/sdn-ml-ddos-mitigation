# Real Datasets for DDoS Detection Evaluation

This project supports evaluation on three well-known intrusion detection datasets.
**Primary evaluation MUST use real datasets** — synthetic-only results should NOT be
cited as accuracy metrics.

## Required Disk Space

Minimum **5 GB** free for extracted CSV files across all datasets.

## Datasets

### 1. CIC-IDS2017

- **URL:** https://www.unb.ca/cic/datasets/ids-2017.html
- **Files needed:** `MachineLearningCSV.zip` (~1.5 GB)
- **Place in:** `datasets/raw/cic-ids2017/`
- **Description:** 5 days of normal and attack traffic (2,830,743 flows). Attacks include
  Brute Force, DoS (Hulk, GoldenEye, Slowhttptest, Slowloris), Heartbleed, Web Attack,
  Infiltration, Botnet, DDoS (LOIT).
- **Known issues:** Contains infinity values, string-typed numeric columns, and
  whitespace in column names. The adapter handles all of these automatically.

```bibtex
@inproceedings{sharafaldin2018toward,
  title={Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization},
  author={Sharafaldin, Iman and Lashkari, Arash Habibi and Ghorbani, Ali A.},
  booktitle={Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP)},
  pages={108--116},
  year={2018},
  organization={SciTePress},
  doi={10.5220/0006639801080116}
}
```

### 2. CIC-DDoS2019

- **URL:** https://www.unb.ca/cic/datasets/ddos-2019.html
- **Files needed:** Training and testing day CSVs
- **Place in:** `datasets/raw/cic-ddos2019/`
- **Description:** 12+ DDoS attack types: DNS, LDAP, MSSQL, NetBIOS, NTP, SNMP, SSDP,
  SYN, TFTP, UDP, UDP-Lag, WebDDoS. Two-day capture (training day + testing day).

```bibtex
@inproceedings{sharafaldin2019developing,
  title={Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy},
  author={Sharafaldin, Iman and Lashkari, Arash Habibi and Sadeghzadeh, Saqib and Ghorbani, Ali A.},
  booktitle={Proceedings of the IEEE International Carnahan Conference on Security Technology (ICCST)},
  pages={1--8},
  year={2019},
  organization={IEEE},
  doi={10.1109/CCST.2019.8888419}
}
```

### 3. UNSW-NB15

- **URL:** https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **Files needed:** `UNSW-NB15_1.csv` through `UNSW-NB15_4.csv`, or the predefined
  train/test split files (`UNSW_NB15_training-set.csv`, `UNSW_NB15_testing-set.csv`)
- **Place in:** `datasets/raw/unsw-nb15/`
- **Description:** 2,540,044 records with 49 features from Argus/Bro-IDS. 9 attack
  categories: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance,
  Shellcode, Worms. Predefined train/test split (175,341 / 82,332).

```bibtex
@inproceedings{moustafa2015unsw,
  title={UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems (UNSW-NB15 Network Data Set)},
  author={Moustafa, Nour and Slay, Jill},
  booktitle={Proceedings of the Military Communications and Information Systems Conference (MilCIS)},
  pages={1--6},
  year={2015},
  organization={IEEE},
  doi={10.1109/MilCIS.2015.7348942}
}
```

## Download Instructions

1. Visit each dataset URL above and follow the download instructions
2. Extract CSV files into the appropriate `datasets/raw/{dataset-name}/` directory
3. Run the verification script:
   ```bash
   python -m sdn_ddos_detector.datasets.download_datasets --dataset all
   ```
4. Train the model on real data:
   ```bash
   python -m sdn_ddos_detector.ml.train --dataset cic-ids2017 --split temporal
   ```

## Directory Structure

```
datasets/
  raw/
    cic-ids2017/          # Place CIC-IDS2017 CSVs here
    cic-ddos2019/         # Place CIC-DDoS2019 CSVs here
    unsw-nb15/            # Place UNSW-NB15 CSVs here
  processed/              # Auto-generated mapped feature CSVs
  synthetic/              # Synthetic baseline data (for comparison only)
```
