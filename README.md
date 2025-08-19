# ACMStorage

> Disclaimer: This content is shared solely for educational discussion. It is not an instruction or endorsement to perform any of the actions described. Attempting these techniques may breach terms of service, licensing agreements, or laws. If you choose to act on any of this information, you do so entirely at your own risk. I disclaim all liability for any outcomes, damages, or repercussions arising from such actions.

A POC that uses Amazon Certificate Manager as a storage service by encoding data to an x.509 v3 extension and storing it in the certificate chain.

See - [https://me.costaskou.com/articles/acmfs/](https://me.costaskou.com/articles/acmfs/)

## How to

```bash
git clone git@github.com:costasko/ACMStorage.git
cd ACMStorage
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
mkdir /mnt/ACMFS
# make sure you have boto3 AWS creds on your profile
sudo python acmfs.py /mnt/ACMFS --foreground
```


Logging is verbose. In a new terminal run

```bash
cp ~/somedata.json /mnt/ACMFS/
cat /mnt/ACMFS/somedata.json
```
