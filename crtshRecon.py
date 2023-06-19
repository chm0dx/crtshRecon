import argparse
import multiprocessing
import psycopg2
import requests
import sys
import time
from datetime import datetime

class Pycrtsh():
    def __init__(self,**kwargs):
        self.conn = None
        self.query_results = []
        self.results = []
        self.attempts = 0
        self.done = multiprocessing.Event()
        self.errors = multiprocessing.Event()
        self.queryerrors = multiprocessing.Event()
        self.__dict__.update(kwargs)
        self.headers = {'authority' : 'crt.sh','accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9','accept-language' : 'en-US,en;q=0.9','cache-control' : 'no-cache','pragma' : 'no-cache','referer' : 'https://groups.google.com/','sec-ch-ua' : '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"','sec-ch-ua-mobile' : '?0','sec-ch-ua-platform' : '"Windows"','sec-fetch-dest' : 'document','sec-fetch-mode' : 'navigate','sec-fetch-site' : 'cross-site','sec-fetch-user' : '?1','upgrade-insecure-requests' : '1','user-agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36'}
        self.url = f"https://crt.sh?q={self.domain}&output=json"
        self.query_string = f"""WITH ci AS (
            SELECT min(sub.CERTIFICATE_ID) ID,
                min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
                array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
                x509_commonName(sub.CERTIFICATE) COMMON_NAME,
                x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,
                x509_notAfter(sub.CERTIFICATE) NOT_AFTER,
                encode(x509_serialNumber(sub.CERTIFICATE), 'hex') SERIAL_NUMBER
                FROM (SELECT *
                        FROM certificate_and_identities cai
                        WHERE plainto_tsquery('certwatch', '{self.domain}') @@ identities(cai.CERTIFICATE)
                            AND cai.NAME_VALUE ILIKE ('%' || '{self.domain}' || '%')
                        LIMIT {self.limit}
                    ) sub
                GROUP BY sub.CERTIFICATE
        )
        SELECT ci.ISSUER_CA_ID,
                ca.NAME ISSUER_NAME,
                ci.COMMON_NAME,
                array_to_string(ci.NAME_VALUES, chr(10)) NAME_VALUE,
                ci.ID ID,
                le.ENTRY_TIMESTAMP,
                ci.NOT_BEFORE,
                ci.NOT_AFTER,
                ci.SERIAL_NUMBER
            FROM ci
                    LEFT JOIN LATERAL (
                        SELECT min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP
                            FROM ct_log_entry ctle
                            WHERE ctle.CERTIFICATE_ID = ci.ID
                    ) le ON TRUE,
                ca
            WHERE ci.ISSUER_CA_ID = ca.ID and ci.NOT_BEFORE > '{self.date}'
            ORDER BY le.ENTRY_TIMESTAMP DESC NULLS LAST;"""

    def query_db(self, send_results):
        while True:
            try:
                if not self.quiet:
                    print("Connecting to crt.sh via DB...")
                self.conn = psycopg2.connect(database="certwatch",host="crt.sh",user="guest",port="5432")
                if not self.quiet:
                    print("Setting up session...")
                self.conn.set_session(readonly=True, autocommit=True)
                cursor = self.conn.cursor()
                if not self.quiet:
                    print("Executing query...")
                cursor.execute(self.query_string)
                results = cursor.fetchall()
                send_results.send(results)
            except psycopg2.Error as e:
                self.queryerrors.set()
                send_results.send(e)
            except Exception as e:
                self.errors.set()
                send_results.send(e)
            if self.conn:
                self.conn.close()
            self.done.set()
            break

    def query_web(self, send_results):
        try:
            if not self.quiet:
                print("Querying crt.sh via web...")
            r = requests.get(self.url, headers=self.headers)
            if r.status_code != 200:
                self.queryerrors.set()
                send_results.send(f"Web request returned {r.status_code}")
            else:
                results = [(result["issuer_ca_id"], result["issuer_name"], result["common_name"], result["name_value"], result["id"], result["entry_timestamp"], result["not_before"], result["not_after"], result["serial_number"]) for result in r.json()]
                send_results.send(results)
        except Exception as e:
            self.errors.set()
            send_results.send(e)
        self.done.set()

    def run_query(self):
        while True:
            try:
                self.done.clear()
                self.errors.clear()
                self.queryerrors.clear()
                results_recv, results_send = multiprocessing.Pipe(False)
                if self.web:
                    query_proc = multiprocessing.Process(target=self.query_web,args=(results_send,))
                elif self.database:
                    query_proc = multiprocessing.Process(target=self.query_db,args=(results_send,))
                query_proc.start()
                self.done.wait(self.timeout)
                query_proc.terminate()
                if self.done.is_set():
                    if self.errors.is_set():
                        sys.exit(f"Terminating: Non-query error ({str(results_recv.recv())})")
                    elif self.queryerrors.is_set() and not self.quiet:
                        print(f"Attempt Failed: {str(results_recv.recv())}")
                    else:
                        self.query_results = results_recv.recv()
                        break
                else:
                    if not self.quiet:
                        print("Attempt Failed: Timeout reached")
                if self.attempts == self.retries:
                    if self.failover:
                        if self.web:
                            self.web = False
                            self.database = True
                            if not self.quiet:
                                print("Failing over to database query...")
                        else:
                            self.database = False
                            self.web = True
                            if not self.quiet:
                                print("Failing over to web query...")
                        self.failover = False
                        self.attempts = 0
                    elif self.database:
                        sys.exit(f"Terminating: Hit retry limit. crt.sh rate limits source IPs and can be unstable. Try modifying the limit (-l) and date (-d) settings.")
                    else:
                        sys.exit(f"Terminating: Hit retry limit. crt.sh rate limits source IPs and can be unstable. Try querying the database using --database instead.")
                else:
                    self.attempts += 1
                    if not self.quiet:
                        print(f"Retrying ({self.attempts}/{self.retries})...")
                    time.sleep(self.sleep)
                
            except KeyboardInterrupt:
                query_proc.terminate()
                sys.exit("\nTerminating: Keyboard interrupt")

        for issuer_id,issuer,common_name,matching_identities,id,logged_at,not_before,not_after,serial_number in self.query_results:
            for name in [common_name, matching_identities]:
                if "\n" in name:
                    for n in name.split("\n"):
                        if " " not in name:
                            if self.primary_domain and self.domain not in name:
                                continue
                            self.results.append(n.replace("*.",""))
                else:
                    if " " not in name:
                        if self.primary_domain and self.domain not in name:
                            continue
                        self.results.append(name.replace("*.",""))
        self.results = sorted(list(set(self.results)), key=lambda i: (i.split(".")[-2], i.count(".") ,i))

        return self.results


if __name__ == "__main__":
    import argparse 
    
    parser = argparse.ArgumentParser()
    parser.add_argument('domain', type=str)
    parser.add_argument("-r","--retries", help="The number of times to retry if there is a failure. Defaults to 2.", type=int, default=2)
    parser.add_argument("-t","--timeout", help="The number of seconds to wait before an attempt times out. Defaults to 60.", type=int, default=60)
    parser.add_argument("-s","--sleep", help="The number of seconds to wait in between attempts. Defaults to 5.", type=int, default=5)
    parser.add_argument("-l","--limit", help="Limit the results in the crt.sh query (DB only). Can help stability. Defaults to 5000.", type=int, default=1000)
    parser.add_argument("-d", "--date", help="Restrict search to certs not valid before the indicated date (DB only). Can help stability. Defaults to 4 years ago.", default=datetime.now().replace(year=datetime.now().year-4).strftime("%Y-%m-%d"))
    parser.add_argument("-p","--primary-domain", help="Restrict results to those related to the passed-in domain", required=False, action="store_true")
    parser.add_argument("-q","--quiet", help="Just print results (and not status messages). Kinda rude, though.", required=False, action="store_true")
    parser.add_argument("-db","--database", help="Query crt.sh via DB. NOTE: The crt.sh DB dataset is not fully up-to-date with the web dataset", required=False, action="store_true", default=False)
    parser.add_argument("-w","--web", help="Query crt.sh via web ", required=False, action="store_true", default=True)
    parser.add_argument("-f","--failover", help="Failover to either web or db queries if the initial option hits the retry limit", required=False, action="store_true", default=False)
    args = parser.parse_args()
    if args.database:
        args.web = False

    pycrtsh = Pycrtsh(**vars(args))
    results = pycrtsh.run_query()

    if not args.quiet:
        print("")
    if not results:
        if args.database:
            print("No results. If you think there should be, try modifying the limit (-l) and date (-d) settings.")
        else:
            print("No results.")
    else:
        for result in results:
            print(result)
