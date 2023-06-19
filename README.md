# crtsh.py

Certificate transparency domain recon via crt.sh. Query either web or DB interfaces with features to add stability

## Install

    git clone 
    cd crtsh.py
    pip install -r requirements.txt

## Use

    usage: crtsh.py [-h] [-r RETRIES] [-t TIMEOUT] [-s SLEEP] [-l LIMIT] [-d DATE] [-p] [-q] [-db] [-w] [-f] domain

    positional arguments:
    domain

    options:
    -h, --help            show this help message and exit
    -r RETRIES, --retries RETRIES
                            The number of times to retry if there is a failure. Defaults to 2.
    -t TIMEOUT, --timeout TIMEOUT
                            The number of seconds to wait before an attempt times out. Defaults to 60.
    -s SLEEP, --sleep SLEEP
                            The number of seconds to wait in between attempts. Defaults to 5.
    -l LIMIT, --limit LIMIT
                            Limit the results in the crt.sh query (DB only). Can help stability. Defaults to 5000.
    -d DATE, --date DATE  Restrict search to certs not valid before the indicated date (DB only). Can help stability. Defaults to 4 years ago.
    -p, --primary-domain  Restrict results to those related to the passed-in domain
    -q, --quiet           Just print results (and not status messages). Kinda rude, though.
    -db, --database       Query crt.sh via DB. NOTE: The crt.sh DB dataset is not fully up-to-date with the web dataset
    -w, --web             Query crt.sh via web
    -f, --failover        Failover to either web or db queries if the initial option hits the retry limit