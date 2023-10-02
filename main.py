from argparse import ArgumentParser
from datetime import datetime
from os import mkdir, path
from re import sub

from Pcap import Pcap
from handlers.YAMLHandler import YAMLHandler

# Current working directory of main file
cwd = path.dirname(path.realpath(__file__))


def main():
    # Arguments were passed
    args = get_args()

    if args.file is not None:
        start(args.file)
        return

    # No arguments were passed
    path_to_pcap_file = input("Enter path to PCAP file: ")
    if not path.exists(path_to_pcap_file):
        raise FileNotFoundError("Could not find PCAP file!")
    start(path_to_pcap_file)


def get_args():
    # Parsing arguments
    parser = ArgumentParser(description="PCAP File analyzer by Martin Szabo")
    parser.add_argument("-f", "--file", dest="file", help="Path to a PCAP file to be scanned")
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


# Used for debugging purposes. Analyzes and tests the validity of all PCAP files. Set the variables inside the function
# to the appropriate values before executing.
def run_tests():
    from utils.Tests import Tests

    pcap_folder = cwd + '/samples'
    yaml_folder = cwd + '/export'
    validator_path = "/home/martin/Repos/pks-course/202324/assignments/1_network_communication_analyzer/validator_yaml_output/validator.py"
    schema_path = "./schemas/schema-all-with-unknown.yaml"
    tests = Tests(pcap_folder, yaml_folder, validator_path, schema_path)

    # Running on all files
    tests.run_on_files()

    # Testing all files
    tests.test_yaml_files()


if __name__ == '__main__':
    main()
