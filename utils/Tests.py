from datetime import datetime
from os import listdir, system, path
from re import sub

from Pcap import Pcap
from handlers.YAMLHandler import YAMLHandler


# Class intended for testing various pcap files all at once
#
# Example of usage:
# pcap_folder = cwd + '/samples'
# yaml_folder = cwd + '/export'
# validator_path = "/home/martin/Repos/pks-course/202324/assignments/1_network_communication_analyzer/validator_yaml_output/validator.py"
# schema_path = "./schemas/schema-all-with-unknown.yaml"
# tests = Tests(pcap_folder, yaml_folder, validator_path, schema_path)
#
# Running on all files
# tests.run_on_files()
#
# Testing all files
# tests.test_yaml_files()


class Tests:

    def __init__(self, pcap_folder_path, yaml_folder_path , validator_script_path, schema_path):
        # PCAP files folder path
        self.pcap_files = Tests.get_paths(pcap_folder_path)

        # Validator paths
        self.validator_script = validator_script_path
        self.schema = schema_path

        # YAML export files folder path
        if not path.exists(yaml_folder_path):
            raise TypeError("Could not find YAML export folder!")
        self.yaml_folder_path = yaml_folder_path

    @staticmethod
    def get_paths(base_dir: str):
        # Lists files in a dir. Returns full path of each file

        files = listdir(base_dir)

        for index, file in enumerate(files):
            files[index] = base_dir + '/' + file
        return files

    def run_on_files(self):
        # Runs PCAP analyzer on a list of PCAP files

        if self.pcap_files is None:
            return

        for file in self.pcap_files:
            self.start(file)

    def start(self, pcap_file_path: str):
        # Runs pcap analyzer on a PCAP file

        pcap_file = Pcap(pcap_file_path)

        # Generates YAMl file from PCAP data
        date_and_time = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
        yaml_name = pcap_file.pcap_name
        yaml_name = sub('(.*\/)|(\.pcap)', '', yaml_name)
        yaml_name = yaml_name+"__"+date_and_time+".yaml"
        YAMLHandler.export_pcap(pcap_file, self.yaml_folder_path+"/"+yaml_name)
        print("File", "\""+yaml_name+"\"", "exported to", "\"" + self.yaml_folder_path + "\"")

    def test_yaml_files(self):
        # Runs YAML validator script on every YAML export file

        if self.yaml_folder_path is None:
            return

        yaml_files = Tests.get_paths(self.yaml_folder_path)

        for file in yaml_files:
            command = "python3  " + self.validator_script + ' -d ' + file + ' -s ' + self.schema
            print("File: \"" + file + "\"")
            system(command)
            print("\n", end='')