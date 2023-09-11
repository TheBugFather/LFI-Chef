""" Built-in modules """
import argparse
import hashlib
import logging
import re
import sys
from datetime import datetime
from pathlib import Path


def windows_sanitize(config_obj: object, line_buffer: bytes) -> bytes:
    """
    Sanitizes the current payload in the line buffer to Windows path specifications.

    :param config_obj:  The program configuration instance.
    :param line_buffer:  The buffer holding the payload to be sanitized.
    :return:  The sanitized windows path payload.
    """
    # Lower case all characters (Windows case-insensitive) #
    line_buffer = line_buffer.lower()

    # If the path slashes are using Linux format #
    if b'/' in line_buffer:
        # Replace the slashes with proper Windows format #
        line_buffer = line_buffer.replace(b'/', b'\\')

    # If a drive was specified #
    if config_obj.drive_letter:
        # If a drive already exists #
        if re.search(config_obj.drive_match, line_buffer):
            # If the current drive letter differs from the one passed in #
            if not line_buffer[:1] == config_obj.drive_letter:
                # Reformat the new drive letter on the beginning of path #
                line_buffer = config_obj.drive_letter + b':' + line_buffer[2:]
        # If no drive exists #
        else:
            # Parse the drive letter into the beginning of the path #
            line_buffer = config_obj.drive_letter + b':' + line_buffer

    # If no drive letter was specified #
    else:
        # If a drive letter exists #
        if re.search(config_obj.drive_match, line_buffer):
            # Remove it from the beginning of the path #
            line_buffer = line_buffer[2:]

    return line_buffer


def sanitize(config_obj: object):
    """
    Sanitizes the input wordlist based on the corresponding operating system. Linux and Mac it
    ensures that external whitespace is stripped and that the slashes are of proper format. Windows
    features the same but also ensures the payload is lowercase and is able to parse in or remove
    system drive letters.

    :return:  Nothing
    """
    filter_dict = {}

    print(f'[+] Sanitizing the input wordlist {config_obj.in_file.name} ..\n')
    try:
        # Open the input wordlist in read mode and output wordlist in append mode #
        with config_obj.in_file.open('rb') as in_file, config_obj.out_file.open('wb') as out_file:
            # Iterate through input wordlist line by line #
            for line in in_file:
                # Copy current line to line buffer #
                line_buffer = line
                # Strip any outer whitespace #
                line_buffer = line_buffer.strip()

                # If the wordlist OS is Windows #
                if config_obj.os == 'windows':
                    # Run the line buffer through the windows sanitization process #
                    line_buffer = windows_sanitize(config_obj, line_buffer)
                # If the wordlist OS is Linux #
                else:
                    # If the path slashes are using Windows format #
                    if b'\\' in line_buffer:
                        # Replace the slashes with proper Linux format #
                        line_buffer = line_buffer.replace(b'\\', b'/')

                # Strip any outer whitespace #
                line_buffer = line_buffer.strip()
                # Hash the contents of parse line in buffer as SHA256 #
                line_hash = hashlib.sha256(line_buffer).hexdigest()

                # If the payload hash is not a key in dict (payload has not been added) #
                if line_hash not in filter_dict:
                    # Assign sanitized payload of current iteration to hash table by hash index #
                    filter_dict[line_hash] = line_buffer
                    # Write the sanitized path to output wordlist #
                    out_file.write(line_buffer + b'\n')

    # If error occurs during file operation #
    except OSError as file_err:
        # Print error, log, and exit program #
        print_err(f'Error occurred during file operation: {file_err}')
        logging.error('Error occurred during file operation: %s', file_err)
        sys.exit(3)

    print(f'[!] LFI {config_obj.os} wordlist sanitization complete .. '
          f'stored at:\n\n\t\t- {config_obj.out_file}\n')


def null_gen(config_obj: object, payload_list: list) -> list:
    """
    Generates null byte injection mutations of the original payload passed and populates generated
    payloads to the payload list.

    :param config_obj:  The program configuration instance.
    :param payload_list:  The payload list for storing mutations per iterations via wordlist.
    :return:  The updated mutation payload list.
    """
    mutations = []

    # Iterate through the list of already existing payloads #
    for payload in payload_list:
        # If the null byte generation mode is appended or both #
        if config_obj.null_byte in ('a', 'b'):
            # Append null byte on the end of current payload #
            payload_buffer = payload + b'%00'
            # Add the payload to the mutations list #
            mutations.append(payload_buffer)

        # If th4e null byte gener
        if config_obj.null_byte in ('p', 'b'):
            # Reset line buffer with null byte prepended on the front of the payload #
            payload_buffer = b'%00' + payload
            # Add the payload to the mutations list #
            mutations.append(payload_buffer)

    return payload_list + mutations


def encoded_gen(config_obj: object, payload_list: list) -> list:
    """
    Generates encoded payload mutations of the original payload passed and populates generated
    payloads to the payload list.

    :param config_obj:  The program configuration instance.
    :param payload_list:  The payload list for storing mutations per iteration via wordlist.
    :return:  The populated mutation payload list.
    """
    mutations = []

    # Iterate through the existing payload list #
    for payload in payload_list:
        # Iterate through the path char mutation encodings #
        for (slash_char, backslash_char,
             period_char, colon_char) in zip(config_obj.slash_chars, config_obj.backslash_chars,
                                             config_obj.period_chars, config_obj.colon_chars):
            # Set the line buffer to the current payload #
            line_buffer = payload
            # If there is a slash mutation to be parsed and a slash in line #
            if slash_char and b'/' in line_buffer:
                # Replace the original slash with mutation #
                line_buffer = line_buffer.replace(b'/', slash_char)

            # If there is a backslash mutation to be parsed and a slash in line #
            if backslash_char and b'\\' in line_buffer:
                # Replace the original backslash with mutation #
                line_buffer = line_buffer.replace(b'\\', backslash_char)

            # If there is a period mutation to be parsed and a period in line # #
            if period_char and b'.' in line_buffer:
                # Replace the period encoding for current iteration #
                line_buffer = line_buffer.replace(b'.', period_char)

            # If mode is windows and there is a mutation to be parsed and line has a colon #
            if config_obj.os == 'windows' and colon_char and b':' in line_buffer:
                # Replace colon character with current parsing character #
                line_buffer = line_buffer.replace(b':', colon_char)

            # Add encoding mutation payload to payload list #
            mutations.append(line_buffer)

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

    # Iterate through the specified path traversal range #
    for traversal in range(config_obj.traversal_start, config_obj.traversal_end + 1):
        # Iterate through the list of already existing payloads #
        for payload in payload_list:
            # Iterate through the list of traversal characters #
            for traversal_set in config_obj.traversal_chars:
                # Unpack the current iteration traversal set #
                path_parse, slash_parse = traversal_set.split(b':')
                # If the OS is Windows #
                if config_obj.os == 'windows':
                    # Replace the backslash characters in path with slash parse #
                    payload_buffer = payload.replace(b'\\', slash_parse)
                # If the OS is Linux or Mac #
                else:
                    # Replace the slash characters in path with slash parse #
                    payload_buffer = payload.replace(b'/', slash_parse)

                # Append generated payload to mutations list #
                mutations.append((path_parse * traversal) + payload_buffer)

    return payload_list + mutations


def generate(config_obj: object):
    """
    Takes the input file and re-replicates each line with copies with path different path encodings
    and saves the output to a fresh wordlist.

    :param config_obj:  The program configuration instance.
    :return:  Nothing
    """
    payload_list = []

    print(f'[+] Generating {config_obj.os} mutation wordlist from {config_obj.in_file.name}\n')
    try:
        # Open the input wordlist in read mode and output wordlist in append mode #
        with config_obj.in_file.open('rb') as in_file, config_obj.out_file.open('wb') as out_file:
            # Iterate through input wordlist line by line #
            for line in in_file:
                # Add original file path payload to list #
                payload_list.append(line.strip())

                # If there are directory traversal mutations to generate #
                if config_obj.traversal_start and config_obj.traversal_end:
                    # Generate path traversal mutations #
                    payload_list = traversal_gen(config_obj, payload_list)

                # If there are encoding mutations to generate #
                if config_obj.slash_chars:
                    # Generate specified encoded mutations #
                    payload_list = encoded_gen(config_obj, payload_list)

                # If there are null byte mutations to generate #
                if config_obj.null_byte:
                    # Generate null byte injection mutations #
                    payload_list = null_gen(config_obj, payload_list)

                # Iterate through generated payload list and write to output file #
                [out_file.write(payload + b'\n') for payload in payload_list]
                # Reset the payload list per iteration #
                payload_list = []

    # If error occurs during file operation #
    except OSError as file_err:
        # Print error, log, and exit program #
        print_err(f'Error occurred during file operation: {file_err}')
        logging.error('Error occurred during file operation: %s', file_err)
        sys.exit(3)

    print(f'[!] LFI {config_obj.os} wordlist generation complete .. '
          f'stored at:\n\n\t\t- {config_obj.out_file}\n')


def main(config_obj: object):
    """
    Launches the program functionality based on specified mode.

    :param config_obj:  The program configuration instance.
    :return:  Nothing
    """
    # TODO: add super sweet program banner with some sort of computer spatula

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
        self.slash_chars = []
        self.backslash_chars = []
        self.period_chars = []
        self.colon_chars = []
        self.traversal_chars = []
        self.traversal_start = None
        self.traversal_end = None
        self.null_byte = False
        self.drive_letter = None
        self.drive_match = re.compile(b'^[A-Za-z]:', re.M)

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
            # If the string path starts with a period specifying current directory #
            if string_path[:1] == '.':
                # Parse the current working directory as base path and create any dirs in path #
                file_path = self.path_parse(string_path, self.cwd)
            # If the string path starts with a tilde specifying the users home directory #
            elif string_path[:1] == '~':
                # Parse the current working directory as home path and create any dirs in path #
                file_path = self.path_parse(string_path, Path.home())
            # If the input is not of correct format #
            else:
                # Print error and exit #
                print_err(f'Error occurred parsing the file path: {file_path}')
                sys.exit(2)

        return file_path

    @staticmethod
    def path_parse(string_path: str, base_path: Path) -> Path:
        """
        Takes the input string and base path and trims the first to characters (./, .\\, ~/, etc.).
        The result is then reformatted to the based in base path and any parent directories in the
        path are created.

        :param string_path:  The old path to be trimmed and reformatted.
        :param base_path:  The base path that the string path with be appended to.
        :return:  The newly formatted pathlib instance.
        """
        # Rewrite string without tilde using index slicing #
        string_parse = string_path[2:]
        # Format the path based on the users home directory #
        file_path = base_path / string_parse
        # Make sure parent directory and its ancestors are created #
        file_path.parent.mkdir(parents=True, exist_ok=True)

        return file_path

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
        # If a single number range was passed in #
        else:
            start_int = 1
            # Attempt to convert string integer to integer #
            end_int = self.int_convert(parsed_input)

        # If one of the integers in traversal range is missing #
        if not start_int or not end_int:
            # Print error and exit #
            print_err('Improper traversal input type, should be number:number '
                      f'but input \"{start_int}:{end_int}\" detected')
            sys.exit(2)

        # If start or end range number are below their minimum or start is greater than the end #
        if start_int < 1 or end_int < 2 or start_int > end_int:
            # Print error and exit #
            print_err('Improper traversal input value, either below minimum threshold or range '
                      f'start is greater than its end but input \"{start_int}:{end_int}\" detected')
            exit(2)

        self.traversal_start = start_int
        self.traversal_end = end_int

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

    def parse_encoding(self, encoding_input: str):
        """
        Takes the input encoding string in any order. Iterates through char by char checking for
        specified encodings. After the path chars encoding list is populated by specified chars in
        available order.

        :param encoding_input:  The parsed encoding string specified by user.
        :return:  Nothing
        """
        # If url encoding was specified #
        if 'u' in encoding_input:
            # If the specified os is windows #
            if conf_obj.os == 'windows':
                self.colon_chars.append(b'%3a')
            # If the specified os is linux/mac #
            else:
                self.colon_chars.append(None)

            self.slash_chars.append(b'%2f')
            self.backslash_chars.append(b'%5c')
            self.period_chars.append(b'%2e')

        # If double url encoding was specified #
        if 'd' in encoding_input:
            # If the specified os is windows #
            if conf_obj.os == 'windows':
                self.colon_chars.append(b'%253a')
            # If the specified os if linux/mac #
            else:
                self.colon_chars.append(None)

            self.slash_chars.append(b'%252f')
            self.backslash_chars.append(b'%255c')
            self.period_chars.append(b'%252e')

        # If 16-bit unicode was specified #
        if 'b' in encoding_input:
            # If the specified os is windows #
            if conf_obj.os == 'windows':
                self.colon_chars += [b'%u003a', b'%u003a']
            # If the specified os if linux/mac #
            else:
                self.colon_chars += [None, None]

            self.slash_chars += [b'%u002f', b'%u2215']
            self.backslash_chars += [b'%u005c', b'%u2216']
            self.period_chars += [b'%u002e', b'%u002e']

        # If overlong utf-8 encoding was specified #
        if 'o' in encoding_input:
            # If the specified os is windows #
            if conf_obj.os == 'windows':
                self.colon_chars += [b'%c0%3a', b'%e0%80%3a', b'%c0%3a']
            # If the specified os if linux/mac #
            else:
                self.colon_chars += [None, None, None]

            self.slash_chars += [b'%c0%af', b'%e0%80%af', b'%c0%2f']
            self.backslash_chars += [b'%c0%5c', b'%c0%80%5c', b'%c0%5c']
            self.period_chars += [b'%c0%2e', b'%e0%40%ae', b'%c0%ae']

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

        try:
            # Set the drive letter in config instance #
            self.drive_letter = drive_letter.lower().encode()

        # If the input drive letter fails to convert to bytes #
        except ValueError:
            # Print error and exit #
            print_err(f'Error occurred converting input drive letter \"{drive_letter}\" to bytes')
            exit(2)


if __name__ == '__main__':
    RET = 0

    # Parse command line arguments #
    arg_parser = argparse.ArgumentParser(description='LFI Chef is a tool that helps automate the '
                                                     'process of LFI wordlist generation with '
                                                     'integrated evasion techniques')
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
                                                      'in a comma-separated with a colon delimiter '
                                                      'between traversal and slash format list like'
                                                      ' ../:/, ....//://, ..\\:\\, etc')
    arg_parser.add_argument('--null_byte', help='Generate null byte payloads based on generated '
                                                'encoding & traversal mutations. Features 3 modes: '
                                                'p (prepend), a (append), b (both)')
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
    # Validate program input wordlist #
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
            # Filter out any items that do have proper colon delimiter while encoding remainders #
            conf_obj.traversal_chars = [item.encode(errors='replace') for item in
                                        conf_obj.traversal_chars if ':' in item]
        # If no traversal char set was specified resulting in default char set #
        else:
            # TODO: add more default path traversal mutations
            # If the target OS is Windows #
            if conf_obj.mode == 'windows':
                conf_obj.traversal_chars = [b'..\\:\\', b'....\\\\:\\\\']
            # If the target OS is Linux #
            else:
                conf_obj.traversal_chars = [b'../:/', b'....//://']

        # Validate the directory traversal integer #
        conf_obj.validate_traversal(parsed_args.traversal)

    # If null byte mutations were specified #
    if parsed_args.null_byte:
        # If the null bytes mutation mode was properly specified #
        if parsed_args.null_byte in ('p', 'a', 'b'):
            # Set null byte mutation mode to on #
            conf_obj.null_byte = parsed_args.null_byte

    # If an output file was specified #
    if parsed_args.out_file:
        # Validate the passed in reference to the output file #
        conf_obj.out_file = conf_obj.validate_file(parsed_args.out_file)
    # If no output file was specified #
    else:
        # Get the current time #
        exec_time = datetime.now()
        # Use the default output file path with current time #
        conf_obj.out_file = conf_obj.cwd / (f'LFI-Chef_{conf_obj.os}_wordlist_{exec_time.hour}_'
                                            f'{exec_time.minute}_{exec_time.second}.txt')

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
