""" Built-in modules """
import argparse
import logging
import sys
from pathlib import Path


def main(config_obj):
    line_buffer = ''
    path_indexes = []

    try:
        # Open the input wordlist in read mode and output wordlist in append mode #
        with config_obj.in_file.open('r', encoding='utf-8') as in_file, \
             config_obj.out_file.open('a', encoding='utf-8') as out_file:
            # Iterate through input wordlist line by line #
            for line in in_file:
                line_buffer += line
                # Reset char counter #
                char_count = 0
                # Iterate through line char by char #
                for char in line:
                    # If the mode is Windows and char is backslash path
                    # or the mode is Linux/Mac and char is slash path #
                    if (config_obj.mode == 'Windows' and char == '\\') \
                    or (config_obj.mode != 'Windows' and char == '/'):
                        # Append current index in line to path indexes for char replacement #
                        path_indexes.append(char_count)

                    char_count += 1

                # If there were path chars in file path to be parsed #
                if path_indexes:
                    # Iterate through the path char replace encodings #
                    for slash_parse in config_obj.path_chars:
                        # Iterate through the tracked indexes where slashes exist #
                        for index in path_indexes:
                            # If the wordlist mode is windows #
                            if config_obj.mode == 'Windows':
                                # Replace backslash with current parsing character #
                                line_buffer[index].replace('\\', slash_parse)
                            # If the wordlist mode is mac or linux #
                            else:
                                # Replace slash with current parsing character #
                                line_buffer[index].replace('/', slash_parse)

                        # Write new line with parsed path characters #
                        out_file.write(line_buffer)

                    # Reset path indexes list per line #
                    path_indexes = []

                # Reset line buffer #
                line_buffer = ''

    # If error occurs during file operation #
    except OSError as file_err:
        # Print error, log, and exit program #
        print_err(f'Error occurred during file operation: {file_err}')
        logging.error('Error occurred during file operation: %s', file_err)
        sys.exit(3)


def print_err(msg: str):
    """
    Prints error message through standard error.

    :param msg:  The error message to be displayed.
    :return:  Nothing
    """
    #  Print error via standard error #
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)


class ProgramConfig:
    """
    Program configuration class for storing program components.
    """
    def __init__(self):
        self.cwd = Path.cwd()
        self.in_file = None
        self.out_file = None
        self.mode = None
        self.path_chars = None

    def validate_file(self, string_path: str, is_required=False) -> Path:
        # Format passed in string path as pathlib object #
        file_path = Path(string_path)
        # Ensure the file exists on disk #
        if is_required:
            # If the file is required and does not exist #
            if not file_path.exists():
                # Print error and exit #
                print_err(f'The file {file_path.name} does not exist on disk')
                sys.exit(2)

        # If the passed in file path is a directory #
        if file_path.is_dir():
            # Print error and exit #
            print_err(f'The file {file_path.name} is a directory, not a file')
            sys.exit(2)

        # If the passed in file path is not absolute #
        if not file_path.is_absolute():
            # Format that path based on the current path #
            file_path = self.cwd / string_path
            # Make sure parent directory and its ancestors are created #
            file_path.parent.mkdir(parents=True, exist_ok=True)

        return file_path


if __name__ == '__main__':
    RET = 0

    # Parse command line arguments #
    arg_parser = argparse.ArgumentParser(description='LFI Chef is a tool that helps automate the '
                                                     'process of LFI wordlist generation')
    arg_parser.add_argument('in_file', help='The path to input file or name of file'
                                            ' if in same directory')
    arg_parser.add_argument('mode', choices=['mac', 'linux', 'windows'],
                            help='The mode of LFI wordlists to generate based on OS')
    arg_parser.add_argument('--out_file', help='The path where the output file is written or '
                                               'name of file if in same directory')
    arg_parser.add_argument('--path_chars', help='The set of comma-separated characters to be used '
                                                 'as alternatives to native file path slashes')
    parsed_args = arg_parser.parse_args()

    # Initialize program configuration class #
    conf_obj = ProgramConfig()
    # Validate required program args #
    conf_obj.in_file = conf_obj.validate_file(parsed_args.in_file, is_required=True)
    # Set program mode in config class #
    conf_obj.mode = parsed_args.mode

    # If an output file arg was specified #
    if parsed_args.out_file:
        conf_obj.out_file = conf_obj.validate_file(parsed_args.out_file)
    else:
        conf_obj.out_file = conf_obj.cwd / f'LFI-Chef_{conf_obj.mode}_wordlist.txt'

    # If path characters to be parsed into output paths were specified #
    if parsed_args.path_chars:
        # Split csv values into list of chars #
        conf_obj.path_chars = parsed_args.path_chars.split(',')
    # Otherwise use default char set #
    else:
        conf_obj.path_chars = ['%2a', '%2b', '%2c', '%2d', '%2e', '%2f']

    # Setup the log file and logging facilities #
    logging.basicConfig(filename='LFI-Chef.log',
                        format='%(asctime)s %(lineno)4d@%(filename)-13s[%(levelname)s]>>  '
                               ' %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    try:
        main(conf_obj)

    # If unexpected exception occurs during program operation #
    except Exception as err:
        # Print, log error and set erroneous exit code #
        print_err(f'Unexpected exception occurred: {err}')
        logging.exception('Unexpected exception occurred: %s', err)
        RET = 1

    sys.exit(RET)
