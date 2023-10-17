import os
import signal
from argparse import ArgumentParser

class Args:

    cdp = False

    def __init__(self):
        # Parsing arguments
        self.parser = ArgumentParser(
            description="PCAP file analyzer by Martin Szabo",
            epilog="""
            \033[0;33mNOTE: You can either run in a single file mode using '-f' switch or multiple files mode with YAML 
            testing using 3 switches (all of the 3 are mandatory for multiple files mode) '--test', '---validator-path',
            '--schema-path'.\033[0m
            """
        )
        self.parser.add_argument("-p", "--protocol", dest="protocol", help="Protocol to lookup")
        self.parser.add_argument("-i", dest="cdp", help="CDP filtracia")

        single_group = self.parser.add_argument_group("Analyze single PCAP file")
        single_group.add_argument("-f", "--file", dest="file", help="Path to a PCAP file to be scanned")

        multiple_group = self.parser.add_argument_group("Analyze multiple PCAP files and test YAML validity")
        multiple_group.add_argument("--test", dest="test_files", help="Path to PCAP files folder to be tested")
        multiple_group.add_argument("--validator-path", dest="validator_path", help="Path to validator executable")
        multiple_group.add_argument("--schema-path", dest="schema_path", help="Path to schema")

        args_dict = self.parser.parse_args().__dict__

        if args_dict["cdp"] is not None:
            Args.cdp = True

        for k, v in args_dict.items():
            setattr(self, k, v)

    def parse_int(self, arg, default_value):
        value = self.__convert_arg_to_int(arg)
        value = value if value is not None else default_value
        return value

    def __convert_arg_to_int(self, arg):
        if arg is not None:
            try:
                return int(arg)
            except ValueError:
                print("Could not convert argument value \"{}\" to integer value!".format(arg))
                if not self.__get_confirmation():
                    pid = os.getpid()
                    os.kill(pid, signal.SIGTERM)
                print("Using default value...\n")
                return None

    @staticmethod
    def __get_confirmation():
        response = ''
        while response != 'Y' and response != 'N':
            print("Do you wish to continue? (y/n): ", end='')
            response = input().upper()
        return response == 'Y'

