from datetime import datetime
from os import mkdir, path
from re import sub
from argparse import ArgumentParser

from Pcap import Pcap
from handlers.YAMLHandler import YAMLHandler

# Current working directory of main file
cwd = path.dirname(path.realpath(__file__))


def main():
    # Arguments were passed
    args = get_args()

    if args.f is not None:
        start(args.f)
        return

    # No arguments were passed
    path_to_pcap_file = input("Enter path to PCAP file: ")
    if not path.exists(path_to_pcap_file):
        raise FileNotFoundError("Could not find PCAP file!")
    start(path_to_pcap_file)


def get_args():
    # Parsing arguments
    parser = ArgumentParser(description="PCAP File analyzer by Martin Szabo")
    parser.add_argument("-f", "--file", help="Path to a PCAP file to be scanned")
    return parser.parse_args()


# Start procedure
def start(pcap_file_path: str):
    # Runs pcap analyzer on a PCAP file

    # Creates export dir
    if not path.exists(cwd + "/export"):
        mkdir(cwd + "/export")

    pcap_file = Pcap(pcap_file_path)

    # Generates YAMl file from PCAP data
    date_and_time = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
    yaml_name = pcap_file.pcap_name
    yaml_name = sub('(.*\/)|(\.pcap)', '', yaml_name)
    yaml_name = yaml_name+"__"+date_and_time+".yaml"
    YAMLHandler.export_pcap(pcap_file, "./export/"+yaml_name)
    print("File", "\""+yaml_name+"\"", "exported to", "\"" + cwd + "/export\"")


if __name__ == '__main__':
    main()
