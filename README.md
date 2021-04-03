# phylum-python-report

Utility script to generate a simple summary report of a verbose job response from the Phylum API

## Prerequisites
* Python 3.x
* Phylum-cli with active user credentials

## Installation
1. Install prerequisite software
2. Clone this repository
```sh
git clone https://github.com/peterjmorgan/phylum-python-report.git
```
3. Change to the phylum-python-report directory
```sh
cd phylum-python-report
```
4. Install python dependencies with pip
```sh
pip install -r requirements.txt
```


## Usage

### Generate a textual report of a job response from the Phylum API
1. Create a JSON file from the verbose response from Phylum API
```sh
phylum-cli status -i <JOB_ID> -V | tail -n+2 > response.json
```
2. Generate report from JSON file
```sh
python3 phylum-python-report.py response.json
```
