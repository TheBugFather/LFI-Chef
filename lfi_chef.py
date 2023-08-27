""" Built-in modules """
import argparse
import hashlib
import logging
import re
import sys
from pathlib import Path


def sanitize(config_obj: object):
    """
    Sanitizes the input wordlist based on the corresponding operating system. Linux and Mac it
    ensures that external whitespace is stripped and that the slashes are of proper format. Windows
    features the same but also ensures the payload is lowercase and is able to parse in or remove
    system drive letters.

    :param config_obj:  The program configuration instance.
    :return:  Nothing
    """
    filter_dict = {}

    try:
        # Open the input wordlist in read mode and output wordlist in append mode #
        with config_obj.in_file.open('r', encoding='utf-8') as in_file, \
             config_obj.out_file.open('a', encoding='utf-8') as out_file:
            # Iterate through input wordlist line by line #
            for line in in_file:
                # Copy current line to line buffer #
                line_buffer = line
                # Strip any outer whitespace #
                line_buffer = line_buffer.strip()

                # If the wordlist OS is Windows #
                if config_obj.os == 'windows':
                    # Lower case all characters (Windows case-insensitive) #
                    line_buffer = line_buffer.lower()

                    # If the path slashes are using Linux format #
                    if '/' in line_buffer:
                        # Replace the slashes with proper Windows format #
                        line_buffer = line_buffer.replace('/', '\\')

                    # If a drive was specified #
                    if config_obj.drive_letter:
                        # If a drive already exists #
                        if re.search(config_obj.drive_match, line_buffer):
                            # If the current drive letter differs from the one passed in #
                            if not line_buffer[:1] == config_obj.drive_letter:
                                # Reformat the new drive letter on the beginning of path #
                                line_buffer = f'{config_obj.drive_letter}:{line_buffer[3:]}'
                        # If no drive exists #
                        else:
                            # Parse the drive letter into the beginning of the path #
                            line_buffer = f'{config_obj.drive_letter}:{line_buffer}'

                    # If no drive letter was specified #
                    else:
                        # If a drive letter exists #
                        if re.search(config_obj.drive_match, line_buffer):
                            # Remove it from the beginning of the path #
                            line_buffer = line_buffer[3:]

                # If the wordlist OS is Linux #
                else:
                    # If the path slashes are using Windows format #
                    if '\\' in line_buffer:
                        # Replace the slashes with proper Linux format #
                        line_buffer = line_buffer.replace('\\', '/')

                # Strip any outer whitespace #
                line_buffer = line_buffer.strip()

                try:
                    # Assign sanitized payload of current iteration to hash table by hash index #
                    filter_dict[hashlib.sha256(line_buffer).hexdigest()] = line_buffer

                # If payload already exists in hash table #
                except KeyError:
                    # Ignore writing to output wordlist by re-iterating #
                    continue

                # Write the sanitized path to output wordlist #
                out_file.write(line_buffer)

    # If error occurs during file operation #
    except OSError as file_err:
        # Print error, log, and exit program #
        print_err(f'Error occurred during file operation: {file_err}')
        logging.error('Error occurred during file operation: %s', file_err)
        sys.exit(3)


def null_gen(payload_list: list) -> list:
    """
    Generates null byte injection mutations of the original payload passed and populates generated
    payloads to the payload list.

    :param payload_list:  The payload list for storing mutations per iterations via wordlist.
    :return:  The updated mutation payload list.
    """
    mutations = []

    # Iterate through the list of already existing payloads #
    for payload in payload_list:
        # Append null byte on the end of current payload #
        payload_buffer = f'{payload}%00'
        # Add the payload to the mutations list #
        mutations.append(payload_buffer)
        # Reset line buffer with null byte prepended on the front of the payload #
        payload_buffer = f'%00{payload}'
        # Add the payload to the mutations list #
        mutations.append(payload_buffer)

    return payload_list + mutations


def traversal_gen(config_obj: object, payload_list: list) -> list:
    """
    Generates path traversal mutations of the original payload passed and populates generated
    payloads to the payload list.

    :param config_obj:  The program configuration instance.
    :param payload_list:  The payload list for storing mutations per iteration via wordlist.
    :return:  The updated mutation payload list.
    """
    mutations = []

    # Iterate through the list of path traversal mutations #
    for traversal in config_obj.traversals:
        # Iterate through the list of already existing payloads #
        for payload in payload_list:
            # Prepend the traversal to the payload as a buffer #
            payload_buffer = traversal + payload
            # Append generated payload to mutations list #
            mutations.append(payload_buffer)

    return payload_list + mutations


def encoded_gen(config_obj: object, line_buffer: str, line: str, payload_list: list) -> list:
    """
    Generates encoded payload mutations of the original payload passed and populates generated
    payloads to the payload list.

    :param config_obj:  The program configuration instance.
    :param line_buffer:  The line buffer for storing the parsed original payload.
    :param line:  The original payload file path read from input wordlist.
    :param payload_list:  The payload list for storing mutations per iteration via wordlist.
    :return:  The populated mutation payload list.
    """
    # Iterate through the path char replace encodings #
    for slash_char, period_char, colon_char in zip(config_obj.path_chars, config_obj.period_chars,
                                                   config_obj.colon_chars):
        # If the wordlist mode is windows #
        if config_obj.os == 'windows':
            # If there is a slash char to parse in current iteration #
            if slash_char:
                # Replace backslash with current parsing character #
                line_buffer = line_buffer.replace('\\', slash_char)

            # If there is colon char to parse in current iteration #
            if colon_char:
                # Replace colon character with current parsing character #
                line_buffer = line_buffer.replace(':', colon_char)

        # If the wordlist mode is mac or linux #
        else:
            # If there is a slash char to parse in current iteration #
            if slash_char:
                # Replace slash with current parsing character #
                line_buffer = line_buffer.replace('/', slash_char)

        # If there is a period character encoding to parse #
        if period_char:
            # Replace the period encoding for current iteration #
            line_buffer = line_buffer.replace('.', period_char)

        # Add encoding mutation payload to payload list #
        payload_list.append(line_buffer)
        # Reset line buffer to original line #
        line_buffer = line

    return payload_list


def generate(config_obj: object):
    """
    Takes the input file and re-replicates each line with copies with path different path encodings
    and saves the output to a fresh wordlist.

    :param config_obj:  The program configuration instance.
    :return:  Nothing
    """
    payload_list = []

    try:
        # Open the input wordlist in read mode and output wordlist in append mode #
        with config_obj.in_file.open('r', encoding='utf-8') as in_file, \
             config_obj.out_file.open('a', encoding='utf-8') as out_file:
            # Iterate through input wordlist line by line #
            for line in in_file:
                # Copy original line into buffer #
                line_buffer = line
                # Add original file path payload to list #
                payload_list.append(line_buffer)

                # If there are encoding mutations to generate #
                if config_obj.path_chars:
                    # Generate specified encoded mutations #
                    payload_list = encoded_gen(config_obj, line_buffer, line, payload_list)

                # If there are directory traversal mutations to generate #
                if config_obj.traversals:
                    # Generate path traversal mutations #
                    payload_list = traversal_gen(config_obj, payload_list)

                # If there are null byte mutations to generate #
                if config_obj.null_byte:
                    # Generate null byte injection mutations #
                    payload_list = null_gen(payload_list)

                # Iterate through generated payload list and write to output file #
                [out_file.write(payload) for payload in payload_list]
                # Reset the payload list per iteration #
                payload_list = []

    # If error occurs during file operation #
    except OSError as file_err:
        # Print error, log, and exit program #
        print_err(f'Error occurred during file operation: {file_err}')
        logging.error('Error occurred during file operation: %s', file_err)
        sys.exit(3)


def main(config_obj: object):
    """
    Launches the program functionality based on specified mode.

    :param config_obj:  The program configuration instance.
    :return:  Nothing
    """
    # If the program mode is wordlist generation #
    if config_obj.mode == 'generate':
        # Call the wordlist generation function #
        generate(config_obj)
    # If the program mode is wordlist sanitization #
    else:
        # Call the wordlist sanitization function #
        sanitize(config_obj)


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
        self.os = None
        self.path_chars = []
        self.period_chars = []
        self.colon_chars = []
        self.traversal_chars = []
        self.traversals = []
        self.null_byte = False
        self.drive_letter = None
        self.drive_match = re.compile('^[A-Za-z]:', re.M)

    def validate_file(self, string_path: str, is_required=False) -> Path:
        """
        Validates the input string path to file on disk. File string is set a pathlib instance, if
        it is required on disk it's existence is confirmed, it also confirms the path does not point
        to a directory, and whether the file path is relative or absolute and handles accordingly.

        :param string_path:  The string path to the file to be read/write.
        :param is_required:  Boolean toggle to specify whether file is required to exist on disk.
        :return:  The validated file path as pathlib instance.
        """
        # Format passed in string path as pathlib object #
        file_path = Path(string_path)
        # Ensure the file exists on disk #
        if is_required:
            # If the file is required and does not exist #
            if not file_path.exists():
                # Print error and exit #
                print_err(f'The file {file_path.name} does not exist on disk')
                sys.exit(2)

        # If the passed in file path is not absolute #
        if not file_path.is_absolute():
            # Format that path based on the current path #
            file_path = self.cwd / string_path
            # Make sure parent directory and its ancestors are created #
            file_path.parent.mkdir(parents=True, exist_ok=True)

        return file_path

    def parse_encoding(self, encoding_input: str):
        """
        Takes the input encoding string in any order. Iterates through char by char checking for
        specified encodings. After the path chars encoding list is populated by specified chars in
        available order.

        :param encoding_input:  The parsed encoding string specified by user.
        :return:  Nothing
        """
        url = False
        double_url = False
        bit_unicode = False
        overlong_encoding = False

        # Iterate through the parsed input encoding specifier string #
        for char in encoding_input:
            # If character specifies url encoding #
            if char == 'u':
                url = True
            # If character specifies double url encoding #
            if char == 'd':
                double_url = True
            # If character specifies 16-bit unicode #
            if char == 'b':
                bit_unicode = True
            # If character specifies overlong utf-8 encoding #
            if char == 'o':
                overlong_encoding = True

        # TODO: add various researched path encodings

        # If url encoding was specified #
        if url:
            # If the specified os is windows #
            if conf_obj.os == 'windows':
                self.path_chars += []
                self.colon_chars += []
            # If the specified os is linux/mac #
            else:
                self.path_chars += []
                self.colon_chars += []

            self.period_chars += []

        # If double url encoding was specified #
        if double_url:
            # If the specified os is windows #
            if conf_obj.os == 'windows':
                self.path_chars += []
                self.colon_chars += []
            # If the specified os if linux/mac #
            else:
                self.path_chars += []
                self.colon_chars += []

            self.period_chars += []

        # If 16-bit unicode was specified #
        if bit_unicode:
            # If the specified os is windows #
            if conf_obj.os == 'windows':
                self.path_chars += []
                self.colon_chars += []
            # If the specified os if linux/mac #
            else:
                self.path_chars += []
                self.colon_chars += []

            self.period_chars += []

        # If overlong utf-8 encoding was specified #
        if overlong_encoding:
            # If the specified os is windows #
            if conf_obj.os == 'windows':
                self.path_chars += []
                self.colon_chars += []
            # If the specified os if linux/mac #
            else:
                self.path_chars += []
                self.colon_chars += []

            self.period_chars += []

    def validate_traversal(self, parsed_input: str):
        """
        Validates the input number of specified path traversal recursions. Then generates the
        range of specified path traversal payload mutations.

        :param parsed_input:  The parsed input arg for number of traversals to generate.
        :return:  Nothing
        """
        # If a specified range was passed in #
        if ':' in parsed_input:
            # Split range by colon delimiter #
            start, end = parsed_input.split(':')
            # Attempt to convert the split range numbers #
            start_int = self.int_convert(start)
            end_int = self.int_convert(end)

            # If the start or end number failed to convert #
            if not start_int or not end_int or start_int > end_int:
                # Print error and exit #
                print_err('Improper traversal range format detected .. '
                          'proper format is <start_number>:<end_number>')
                sys.exit(2)

            # Iterate through range and generate traversals #
            for num_traverse in range(start_int, end_int + 1):
                # Generate a list of traversal mutations based on current iteration multiplier #
                current_payloads = self.traversal_payload_gen(num_traverse)
                # Add the resulting list of payloads to traversals list #
                self.traversals += current_payloads

        # If a single number range was passed in #
        else:
            # Attempt to convert string integer to integer #
            int_input = self.int_convert(parsed_input)
            # If the string integer conversion failed to convert #
            if not int_input:
                # Print error and exit #
                print_err('Input number specified for traversal mutations failed to '
                          f'convert: {parsed_input}')
                sys.exit(2)

            # If the parsed integer input is not greater than 0 #
            if not int_input > 0:
                # Print error and exit #
                print_err(f'The input integer {parsed_input} should be a positive integer '
                          'greater than zero')
                sys.exit(2)

            # Iterate through range and generate traversals #
            for num_traverse in range(int_input + 1):
                # Generate a list of traversal mutations based on current iteration multiplier #
                current_payloads = self.traversal_payload_gen(num_traverse)
                # Add the resulting list of payloads to traversals list #
                self.traversals += current_payloads

    @staticmethod
    def int_convert(str_int: str):
        """
        Converts string integer back to its native integer format

        :param str_int:  The string integer to be converter back to integer.
        :return:  Converted integer on success, None on failure.
        """
        try:
            # Convert string integer to raw integer #
            int_res = int(str_int)

        # If error occurs converting integer to string #
        except ValueError as conversion_err:
            print_err(f'Error occurred converting string integer to integer: {conversion_err}')
            int_res = None

        return int_res

    def traversal_payload_gen(self, traversal_mul: int) -> list:
        """
        Takes the passed in traversal multiplier and generates the current recursion number with
        each mutation in the traversal chars list.

        :param traversal_mul:  The number of times to mutate the traversal character mutation.
        :return:  The list of generated mutations for the current traversal multiplier.
        """
        traversals = []
        # Iterate through the traversal chars and add the current mutations multiplier to list #
        return [traversals.append(char * traversal_mul) for char in self.traversal_chars]

    def validate_drive(self, drive_letter: str):
        """
        Ensures the passed in drive letter is of proper format.

        :param drive_letter:  The drive letter to validate.
        :return:  Nothing
        """
        # If the drive letter is not a single character #
        if not re.match(r'[A-Za-z]', drive_letter):
            # Print error and exit #
            print_err(f'Specified Windows drive letter \"{drive_letter}\" is not of proper format')
            exit(2)

        # Ensure drive letter is lowercase #
        drive_letter = drive_letter.lower()
        # Set the drive letter in config instance #
        self.drive_letter = drive_letter


if __name__ == '__main__':
    RET = 0

    # Parse command line arguments #
    arg_parser = argparse.ArgumentParser(description='LFI Chef is a tool that helps automate the '
                                                     'process of LFI wordlist generation')
    arg_parser.add_argument('in_file', help='The path to input file or name of file'
                                            ' if in same directory')
    arg_parser.add_argument('mode', choices=['generate', 'sanitize'],
                            help='The programs mode of operation')
    arg_parser.add_argument('os', choices=['mac', 'linux', 'windows'],
                            help='The OS of the LFI wordlist to generate')
    arg_parser.add_argument('--encoding', help='Specify the encodings to use with path generation. '
                                               'u => url-encoding, d => double url-encoding, '
                                               'b => 16-bit unicode, o => overlong utf-8 encoding. '
                                               'Example: udbo OR duo OR ou .. in any order/combo')
    arg_parser.add_argument('--traversal', help='Specify the number of recursions to generate '
                                                'directory traversal payloads or specify specific'
                                                'ranges like 2:4 generating recursions 2-4')
    arg_parser.add_argument('--traversal_chars', help='Specify the custom traversal payload chars'
                                                      'in a comma-separated list like ../,..%2f,'
                                                      '....//,....%2f%2f')
    arg_parser.add_argument('--null_byte', default=False, type=bool,
                            help='Boolean toggle to generate null byte payloads based on generated '
                                 'encoding & traversal mutations')
    arg_parser.add_argument('--out_file', help='The path where the output file is written or '
                                               'name of file if in same directory')
    arg_parser.add_argument('--drive', help='The Windows drive associated with sanitization mode. '
                                            'If drive letter specified (Ex: A .. A-Z available), it'
                                            'will be parsed at the beginning of path unless it '
                                            'already exists. If not specified it will strip any '
                                            'drive letters detected')
    parsed_args = arg_parser.parse_args()

    # Initialize program configuration class #
    conf_obj = ProgramConfig()
    # Validate required program args #
    conf_obj.in_file = conf_obj.validate_file(parsed_args.in_file, is_required=True)
    # Set program mode in config class #
    conf_obj.mode = parsed_args.mode
    # Set program os in config class #
    conf_obj.os = parsed_args.os

    # If any encodings were specified #
    if parsed_args.encoding:
        # Parse the specified encodings into the path chars list in config class #
        conf_obj.parse_encoding(parsed_args.encoding)

    # If directory traversal mutations were specified #
    if parsed_args.traversal:
        # If a set of custom traversal chars were passed in #
        if parsed_args.traversal_chars:
            # Split comma-separated values into list #
            conf_obj.traversal_chars = parsed_args.traversal_chars.split(',')
        # If no traversal char set was specified resulting in default char set #
        else:
            # TODO: add more default path traversal mutations
            # If the target OS is Windows #
            if conf_obj.mode == 'windows':
                conf_obj.traversal_chars = ['..\\', '....\\\\']
            # If the target OS is Linux #
            else:
                conf_obj.traversal_chars = ['../', '..//']

        # Validate the directory traversal integer #
        conf_obj.validate_traversal(parsed_args.traversal)

    # If null byte mutations were specified #
    if parsed_args.null_byte:
        # Set null byte mutation mode to on #
        conf_obj.null_byte = True

    # If an output file was specified #
    if parsed_args.out_file:
        # Validate the passed in reference to the output file #
        conf_obj.out_file = conf_obj.validate_file(parsed_args.out_file)
    # If no output file was specified #
    else:
        # Use the default output file path #
        conf_obj.out_file = conf_obj.cwd / f'LFI-Chef_{conf_obj.os}_wordlist.txt'

    # If a specific Windows drive was specified for sanitization #
    if parsed_args.drive:
        # Validate that drive letter is proper format #
        conf_obj.validate_drive(parsed_args.drive)

    # Set up the log file and logging facilities #
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
