# Cryptonote Funding System 

## Description
The Cryptonote Funding System was written entirely in Python. It was originally developed for the Wownero currency but later updated by various community members to be accepted for AEON, Masari and more.

## installation (locally)

Better instructions to follow in the future.

Create a Postgres user/database for this project

```
sudo apt install python-virtualenv python3 redis-server postgresql-server-dev-* postgresql postgres-client python-pip virtualenv
git clone ...
cd ffs_site
virtualenv -p /usr/bin/python3 venv
source venv/bin/activate
pip install -r requirements.txt
cp settings.py_example settings.py
- change settings accordingly
python run_dev.py
```

### to-do

- rate limit posting of proposals per user

https://imgur.com/KKzFQe9
https://imgur.com/Dl3wRgD

- Define coin variable
- Define one exchange API URL
- Automated setup