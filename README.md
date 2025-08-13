# ACMStorage

A POC that uses Amazon Certificate Manager as a storage service by encoding data to an x.509 v3 extension and storing it in the certificate chain.

See - 

## How to

```bash
git clone git@github.com:costasko/ACMStorage.git
cd ACMStorage
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
mkdir /mnt/ACMFS
sudo python3 acmfs.py /mnt/ACMFS --foreground
cp ~/data.json /mnt/ACMFS/
```
