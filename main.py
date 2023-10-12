from argparse import ArgumentParser
from datetime import datetime
from os import mkdir, path
from re import sub

from Pcap import Pcap
from handlers.YAMLHandler import YAMLHandler
from utils.Args import Args

# Current working directory of main file
cwd = path.dirname(path.realpath(__file__))


def main():
    # Arguments were passed
    args = Args()

    if args.file is not None and args.protocol is not None:
        start(args.file, args.protocol)
        return
    elif args.file is not None:
        start(args.file)
        return
    elif args.test_files is not None and args.validator_path is not None and args.schema_path is not None:
        run_tests(args.test_files, args.validator_path, args.schema_path)
        return

    # No arguments were passed
    path_to_pcap_file = input("Enter path to PCAP file: ")
    if not path.exists(path_to_pcap_file):
        raise FileNotFoundError("Could not find PCAP file!")
    start(path_to_pcap_file)


# Start procedure
def start(pcap_file_path: str, protocol=None):
    # Runs pcap analyzer on a PCAP file

    # Creates export dir
    if not path.exists(cwd + "/export"):
        mkdir(cwd + "/export")

    pcap_file = Pcap(pcap_file_path)

    if protocol is not None:
        result = pcap_file.filter_out(protocol)
        if not result:
            print("Error invalid protocol")
            return

    # Generates YAMl file from PCAP data
    date_and_time = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
    yaml_name = pcap_file.pcap_name
    yaml_name = sub('(.*\/)|(\.pcap)', '', yaml_name)
    yaml_name = yaml_name+"__"+date_and_time+".yaml"
    YAMLHandler.export_pcap(pcap_file, "./export/"+yaml_name)
    print("File", "\""+yaml_name+"\"", "exported to", "\"" + cwd + "/export\"")


# Used for debugging purposes. Analyzes and tests the validity of all PCAP files. Set the variables inside the function
# to the appropriate values before executing.
def run_tests(pcap_folder, validator_path, schema_path):
    from utils.Tests import Tests

    yaml_folder = cwd + '/export'
    tests = Tests(pcap_folder, yaml_folder, validator_path, schema_path)

    # Running on all files
    tests.run_on_files()

    # Testing all files
    tests.test_yaml_files()


if __name__ == '__main__':
    main()
