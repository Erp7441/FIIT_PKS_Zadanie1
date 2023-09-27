from datetime import datetime
from os import listdir, mkdir, path, system
from re import sub

from Pcap import Pcap
from handlers.YAMLHandler import YAMLHandler


cwd = path.dirname(path.realpath(__file__))


def main():
    # Running on single file
    start('./samples/trace-26.pcap')

    # Running on all files (Uncomment to enable)
    # pcap_files = get_paths(cwd + '/samples')
    # run_on_files(pcap_files)

    # Testing all files (Uncomment to enable)
    # validator_script = "/home/martin/Repos/pks-course/202324/assignments/1_network_communication_analyzer/validator_yaml_output/validator.py"
    # schema = "/home/martin/Repos/pks-course/202324/assignments/1_network_communication_analyzer/validator_yaml_output/schemas/schema-all.yaml"
    # yaml_files = get_paths(cwd + '/export')
    # test_yaml_files(yaml_files, validator_script, schema)


def start(pcap_file_path: str):
    # Creates export dir
    if not path.exists(cwd + "/export"):
        mkdir(cwd + "/export")

    date_and_time = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
    pcap_file = Pcap(pcap_file_path)

    yaml_name = pcap_file.pcap_name
    yaml_name = sub('(.*\/)|(\.pcap)', '', yaml_name)
    YAMLHandler.export_pcap(pcap_file, "./export/"+yaml_name+"__"+date_and_time+".yaml")


def get_paths(base_dir: str):
    files = listdir(base_dir)

    for index, file in enumerate(files):
        files[index] = base_dir + '/' + file
    return files


def run_on_files(pcap_files: list):
    for file in pcap_files:
        start(file)


def test_yaml_files(yaml_file_paths: list, validator_script: str, schema: str):
    for file in yaml_file_paths:
        command = "python3  " + validator_script + ' -d ' + file + ' -s ' + schema
        print("File: \"" + file + "\"")
        system(command)
        print("\n", end='')


if __name__ == '__main__':
    main()


# Kuriozity
# trace-27.pcap --> 1532 frame