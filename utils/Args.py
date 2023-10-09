import os
import signal
from argparse import ArgumentParser


class Args:

    def __init__(self):
        # Parsing arguments
        self.parser = ArgumentParser(description="PCAP file analyzer by Martin Szabo")
        self.parser.add_argument("-f", "--file", dest="file", help="Path to a PCAP file to be scanned")
        self.parser.add_argument("--test", dest="test_files", help="Path to PCAP files folder to be tested")
        self.parser.add_argument("--validator-path", dest="validator_path", help="Path to validator executable")
        self.parser.add_argument("--schema-path", dest="schema_path", help="Path to schemas")

        args_dict = self.parser.parse_args().__dict__

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
