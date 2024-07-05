import argparse
import threading
import datetime
import logging
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import curses


logging.basicConfig(filename='/backup/backup.log', level=logging.INFO, format='%(asctime)s %(message)s')


packets = []


def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        else:
            proto = "Other"

        packets.append((ip_src, ip_dst, proto))


def start_capture(interface):
    sniff(iface=interface, prn=packet_callback, store=False)


def display_packets(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(1)
    stdscr.timeout(100)

    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Network Analyzer Tool - Press 'q' to exit")
        stdscr.addstr(1, 0, "Source IP\tDestination IP\tProtocol")
        stdscr.addstr(2, 0, "-"*50)

        for idx, (ip_src, ip_dst, proto) in enumerate(packets[-20:], start=3):
            stdscr.addstr(idx, 0, f"{ip_src}\t{ip_dst}\t{proto}")

        stdscr.refresh()

        key = stdscr.getch()
        if key == ord('q'):
            break


def display_logo(stdscr):
    logo = """
    _______                   _   _            _                     
   |__   __|                 | | (_)          | |                    
      | | ___  __ _ _ __ __ _| |_ _  ___  _ __| |_ ___ _ __ ___  ___ 
      | |/ _ \/ _` | '__/ _` | __| |/ _ \| '__| __/ _ \ '__/ __|/ _ \\
      | |  __/ (_| | | | (_| | |_| | (_) | |  | ||  __/ |  \__ \  __/
      |_|\___|\__, |_|  \__,_|\__|_|\___/|_|   \__\___|_|  |___/\___|
               __/ |                                                 
              |___/                                                  
    """
    stdscr.clear()
    stdscr.addstr(logo)
    stdscr.refresh()
    stdscr.getch()


def main(interface):
    
    curses.wrapper(display_logo)

    
    capture_thread = threading.Thread(target=start_capture, args=(interface,))
    capture_thread.start()


    curses.wrapper(display_packets)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Analyzer Tool")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to capture packets from")
    args = parser.parse_args()

    main(args.interface)

