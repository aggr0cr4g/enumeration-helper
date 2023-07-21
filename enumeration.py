import argparse
import subprocess
import threading
import re
from concurrent.futures import ThreadPoolExecutor
#from multiprocessing import Pool
#from multiprocessing import Process
import os
import sys

class SetupTools:
    def __init__(self):
        self.tools_path = os.path.expanduser("~/Tools")
        self.gf_path = os.path.expanduser("~/.gf")
        self.config_path = os.path.expanduser("~/.config")
        self.lists_path = os.path.expanduser("~/Lists")
        self.go_tools = [
            "github.com/tomnomnom/fff",
            "github.com/lc/gau/v2/cmd/gau",
            "github.com/ferreiraklet/airixss",
            "github.com/takshal/freq",
            "github.com/deletescape/goop",
            "github.com/hakluke/hakrawler",
            "github.com/tomnomnom/httprobe",
            "github.com/tomnomnom/meg",
            "github.com/hakluke/haklistgen",
            "github.com/hakluke/haktldextract",
            "github.com/hakluke/hakcheckurl",
            "github.com/tomnomnom/hacks/tojson",
            "github.com/sensepost/gowitness",
            "github.com/shenwei356/rush",
            "github.com/projectdiscovery/naabu/cmd/naabu",
            "github.com/hakluke/hakcheckurl",
            "github.com/projectdiscovery/shuffledns/cmd/shuffledns",
            "github.com/root4loot/rescope",
            "github.com/tomnomnom/gron",
            "github.com/tomnomnom/hacks/html-tool",
            "github.com/projectdiscovery/chaos-client/cmd/chaos",
            "github.com/tomnomnom/gf",
            "github.com/tomnomnom/qsreplace",
            "github.com/OWASP/Amass/v3/...",
            "github.com/ffuf/ffuf",
            "github.com/tomnomnom/assetfinder",
            "github.com/gwen001/github-subdomains",
            "github.com/dwisiswant0/cf-check",
            "github.com/tomnomnom/hacks/waybackurls",
            "github.com/projectdiscovery/nuclei/v2/cmd/nuclei",
            "github.com/tomnomnom/anew",
            "github.com/projectdiscovery/notify/cmd/notify",
            "github.com/daehee/mildew/cmd/mildew",
            "github.com/m4dm0e/dirdar",
            "github.com/tomnomnom/unfurl",
            "github.com/projectdiscovery/shuffledns/cmd/shuffledns",
            "github.com/projectdiscovery/httpx/cmd/httpx",
            "github.com/gwen001/github-endpoints",
            "github.com/projectdiscovery/dnsx/cmd/dnsx",
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
            "github.com/bp0lr/gauplus",
            "github.com/lc/subjs",
            "github.com/hiddengearz/jsubfinder",
            "github.com/KathanP19/Gxss",
            "github.com/jaeles-project/gospider",
            "github.com/cgboal/sonarsearch/crobat",
            "github.com/hahwul/dalfox/v2",
            "github.com/d3mondev/puredns/v2",
            "github.com/edoardottt/cariddi",
            "github.com/projectdiscovery/interactsh/cmd/interactsh-client",
            "github.com/tomnomnom/hacks/kxss",
            "github.com/003random/getJS",
            "github.com/hakluke/hakrevdns"
        ]
        self.git_repos = [
            "https://github.com/tomnomnom/gf",
            "https://github.com/1ndianl33t/Gf-Patterns",
            "https://github.com/m4ll0k/SecretFinder",
            "https://github.com/m4ll0k/BBTz",
            "https://github.com/devanshbatham/ParamSpider",
            "https://github.com/Ekultek/WhatWaf",
            "https://github.com/EnableSecurity/wafw00f"
        ]
        self.gf_repos = [
            "https://github.com/tomnomnom/gfdecos",
            "https://github.com/r00tkie/grep-pattern",
            "https://github.com/mrofisr/gf-patterns",
            "https://github.com/robre/gf-patterns",
            "https://github.com/1ndianl33t/Gf-Patterns",
            "https://github.com/dwisiswant0/gf-secrets",
            "https://github.com/bp0lr/myGF_patterns",
            "https://github.com/cypher3107/GF-Patterns",
            "https://github.com/Matir/gf-patterns",
            "https://github.com/Isaac-The-Brave/GF-Patterns-Redux",
            "https://github.com/arthur4ires/gfPatterns",
            "https://github.com/R0X4R/Garud",
            "https://github.com/cypher3107/GF-Patterns",
            "https://github.com/seqrity/Allin1gf",
            "https://github.com/Jude-Paul/GF-Patterns-For-Dangerous-PHP-Functions",
            "https://github.com/NitinYadav00/gf-patterns",
            "https://github.com/scumdestroy/YouthCrew-GF-Patterns"
        ]
    
    def install_waf_tools(self):
        print("Installing WafW00F...")
        os.system("pip3 install wafw00f")
        print("WafW00F has been installed.")
    
    def clone_and_search(self, repo):
        # Check if the repository is public
        response = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", repo], capture_output=True)
        if response.stdout.decode().strip() == "200":
            # Clone the repository with --depth 1 option to only download the latest commit
            print(f"Cloning {repo}")
            subprocess.run(["git", "clone", "--depth", "1", repo])

            # Search for JSON patterns recursively
            repo_name = repo.split("/")[-1]
            for root, dirs, files in os.walk(repo_name):
                for file in files:
                    if file.endswith((".json", ".JSON", ".geojson", ".GeoJSON")):
                        os.rename(os.path.join(root, file), os.path.join(self.gf_path, file))

            # Remove the cloned repository
            print(f"Removing {repo}")
            subprocess.run(["rm", "-rf", repo_name])
        else:
            print(f"{repo} is no longer public or has been deleted, skipping.")

    def setup_gf_patterns(self):
        for repo in self.gf_repos:
            self.clone_and_search(repo)

    def check_go_installed(self):
        try:
            subprocess.check_output(["go", "version"])
            return True
        except subprocess.CalledProcessError:
            return False

    def create_directories(self):
        os.makedirs(self.gf_path, exist_ok=True)
        os.makedirs(self.tools_path, exist_ok=True)
        os.makedirs(os.path.join(self.config_path, "notify"), exist_ok=True)
        os.makedirs(os.path.join(self.config_path, "amass"), exist_ok=True)
        os.makedirs(os.path.join(self.config_path, "subfinder"), exist_ok=True)
        os.makedirs(self.lists_path, exist_ok=True)

    def download_files(self):
        os.system("wget -nc -O ~/Lists/XSS-OFJAAAH.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-OFJAAAH.txt")
        os.system("wget -nc -O ~/Lists/params.txt https://raw.githubusercontent.com/s0md3v/Arjun/master/arjun/db/params.txt")
        os.system("wget -nc -O ~/.gf/potential.json https://raw.githubusercontent.com/devanshbatham/ParamSpider/master/gf_profiles/potential.json")
        # Aquatone
        os.system("wget -nc -O ~/Tools/aquatone_linux_amd64_1.7.0.zip https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip")
        os.system("unzip -o ~/Tools/aquatone_linux_amd64_1.7.0.zip -d ~/Tools/")
        os.system("rm ~/Tools/LICENSE.txt ~/Tools/README.md ~/Tools/aquatone_linux_amd64_1.7.0.zip")

    def install_go_tools(self):

        if not self.check_go_installed():
            print("Go is not installed. Please install Go before running the setup.")
            print("You can install Go with the following commands:")
            print("1. Download the Go tarball:")
            print("   curl https://go.dev/dl/go1.20.5.linux-amd64.tar.gz -o go1.20.5.linux-amd64.tar.gz")
            print("2. Extract the tarball:")
            print("   sudo tar -C /usr/local -xzf go1.20.5.linux-amd64.tar.gz")
            print("3. Add Go to your PATH:")
            print("   echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc")
            print("4. Reload your .bashrc to apply the changes:")
            print("   source ~/.bashrc")
            sys.exit(1)
        for tool in self.go_tools:
            os.system(f"go install {tool}@latest")

    def clone_git_repos(self):
        for repo in self.git_repos:
            repo_name = repo.split("/")[-1]
            os.system(f"git clone {repo} {self.tools_path}/{repo_name}")

    def run_all(self):
        self.create_directories()
        self.setup_gf_patterns()
        self.download_files()
        self.install_go_tools()
        self.clone_git_repos()
        self.install_waf_tools()

class WAFDetection(threading.Thread):
    def __init__(self, url):
        threading.Thread.__init__(self)
        self.tools_path = os.path.expanduser("~/Tools")
        self.url = url

    def run(self):
        # Run different tools for WAF Detection
        self.whatwaf()
        self.wafw00f()
        self.nmap_waf_nse()

    def whatwaf(self):
        # Run WhatWaf to detect WAF
        print(subprocess.run(["python", "WhatWaf/whatwaf.py", "-u", self.url], capture_output=True, text=True).stdout)

    def wafw00f(self):
        # Run WAFW00F to detect WAF
        print(subprocess.run(["wafw00f", self.url], capture_output=True, text=True).stdout)

    def nmap_waf_nse(self):
        # Run Nmap to detect WAF
        print(subprocess.run(["nmap", "-p", "80,443", "--script", "http-waf-detect", self.url], capture_output=True, text=True).stdout)


class HistoricalEnumeration(threading.Thread):
    def __init__(self, url):
        threading.Thread.__init__(self)
        self.url = url

    def run(self):
        # Run gau tool for historical enumeration
        self.gau()

    def gau(self):
        def clean_gf_files(directory):
            # Regular expression to match "<filename>:<lineNumber>:<url>"
            #pattern = re.compile(r'^.*?:\d+:')
            pattern = re.compile(r'^.*:\d+:')

            # Iterate over all files in the directory
            for filename in os.listdir(directory):
                filepath = os.path.join(directory, filename)

                # Only process gf text files
                if os.path.isfile(filepath) and filepath.endswith('.txt'):
                    with open(filepath, 'r') as file:
                        lines = file.readlines()

                    # Remove "<filename>:<lineNumber>:" from each line
                    cleaned_lines = [pattern.sub('', line) for line in lines]

                    # Write the cleaned lines back to the file
                    with open(filepath, 'w') as file:
                        file.writelines(cleaned_lines)

        # Create directories if they don't exist
        original_dir = os.getcwd()
        os.makedirs(f"./Gau/", exist_ok=True)
        os.makedirs(f"./Gau/{self.url}", exist_ok=True)

        os.chdir(f"./Gau/{self.url}")
        
        # Run gauplus to fetch known URLs from a domain and save to a file
        print(f"Running gau for {self.url}")
        # Using Popen to avoid hanging
        command = f'echo "{self.url}" | gau > Gau_{self.url}.txt'
        print(f"Running Command: {command}")
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        # Get a list of all gf patterns
        gf_patterns = subprocess.run(["gf", "-list"], capture_output=True, text=True).stdout.splitlines()
        for pattern in gf_patterns:
            try:
                command = f"cat Gau_{self.url}.txt | sort -u | gf {pattern} > {self.url}_{pattern.upper()}.txt"
                print(f"Running Command: {command}")
                result = subprocess.run(command, shell=True, text=True, capture_output=True)

                if result.returncode != 0:
                    print(f"Error processing pattern {pattern}: {result.stderr}")
                
                # check file size and remove if empty
                file_path = f"{self.url}_{pattern.upper()}.txt"
                if os.path.getsize(file_path) == 0:
                    print(f"Removing empty file: {file_path}")
                    os.remove(file_path)
            except Exception as e:
                print(f"Error processing pattern {pattern}: {str(e)}")

        # Call the function on your directory
        clean_gf_files(os.getcwd())

        os.chdir(original_dir)


def run_waf_detection(args):
    # Run WAF Detection in a separate thread
    waf_detection_thread = WAFDetection(args.url)
    waf_detection_thread.start()


def run_historical_enumeration(args):
    # If a URL is provided, run Historical Enumeration for the URL
    if args.url:
        historical_enum_thread = HistoricalEnumeration(args.url)
        historical_enum_thread.start()
        historical_enum_thread.join()  # Wait for the thread to finish
    
    # If a file is provided, run Historical Enumeration for each URL in the file
    elif args.file:
        print("Still working on the threading for providing a file. Simple solution for now: ")
        print('interlace -tL ./urls.txt -threads 5 -c"python3 eumeration.py hist --url _target_"')
        '''
        with open(args.file, 'r') as file:
            urls = file.read().splitlines()
        for url in urls:
            print(url)
            historical_enum_thread = HistoricalEnumeration(url)
            historical_enum_thread.start()
            historical_enum_thread.join()  # Wait for the thread to finish        
        '''


if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description="Automated Enumeration Script")
    subparsers = parser.add_subparsers(dest="command", help="Technique for enumeration")

    # Setup command
    parser_setup = subparsers.add_parser("setup", help="Setup tools and environment")

    # WAF Detection command
    parser_waf = subparsers.add_parser("waf", help="WAF Detection")
    parser_waf.add_argument("--url", required=True, help="Target URL")

    # Historical Enumeration command
    parser_hist = subparsers.add_parser("hist", help="Historical Enumeration")
    group = parser_hist.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Target URL")
    group.add_argument("--file", help="File containing a list of URLs one per line")

    # Parse the arguments
    args = parser.parse_args()

    # Execute based on command
    if args.command == "setup":
        setup_tools = SetupTools()
        setup_tools.run_all()
    elif args.command == "waf":
        waf_enum = WAFDetection(args.url)
        waf_enum.start()
    elif args.command == "hist":
        run_historical_enumeration(args)
        #hist_enum.start()
    else:
        print("Please specify a valid command. Use -h for help.")