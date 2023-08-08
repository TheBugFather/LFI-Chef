""" Built-in modules """
import argparse
import logging
import sys
from pathlib import Path


def print_err(msg: str):
    """
    Prints error message through standard error.

    :param msg:  The error message to be displayed.
    :return:  Nothing
    """
    #  Print error via standard error #
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)


def main(config_obj):
    pass


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
            print_err('Passed in file path does not exist on file system')
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
    arg_parser.add_argument('mode', choices=['linux', 'windows'], help='The mode of LFI wordlists '
                                                                       'to generate based on OS')
    arg_parser.add_argument('--out_file', help='The path where the output file is written or '
                                               'name of file if in same directory')
    arg_parser.add_argument('--path_chars', help='The set of characters to be used as alternatives '
                                                 'to native file path slashes Ex: %2f,\\,/')
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

    # If path characters to be parsed into output paths were specified #
    if parsed_args.path_chars:
        # Split csv values into list of chars #
        conf_obj.path_chars = parsed_args.path_chars.split(',')
    # Otherwise use default char set #
    else:
        conf_obj.path_chars = ['%2f']

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





# def error_query(err_path: str, err_mode: str, err_obj):
#     """
#     Looks up the errno message to get description.
#
#     :param err_path:  The path to the file where the error occurred.
#     :param err_mode:  The file mode used during the error.
#     :param err_obj:  The error message instance.
#     :return:  Nothing
#     """
#     # If file does not exist #
#     if err_obj.errno == errno.ENOENT:
#         print_err(f'{err_path} does not exist')
#         logging.error('%s does not exist', err_path)
#
#     # If the file does not have read/write access #
#     elif err_obj.errno == errno.EPERM:
#         print_err(f'{err_path} does not have permissions for {err_mode}'
#                   ' file mode, if file exists confirm it is closed')
#         logging.error('%s does not have permissions for %s file mode, if file '
#                       'exists confirm it is closed', err_path, err_mode)
#
#     # File IO error occurred #
#     elif err_obj.errno == errno.EIO:
#         print_err(f'IO error occurred during {err_mode} mode on {err_path}')
#         logging.error('IO error occurred during %s mode on %s', err_mode, err_path)
#
#     # If other unexpected file operation error occurs #
#     else:
#         print_err(f'Unexpected file operation error occurred accessing {err_path}: {err_obj.errno}')
#         logging.error('Unexpected file operation error occurred accessing %s: %s',
#                       err_path, err_obj.errno)




