<div align="center" style="font-family: monospace">
<h1>LFI-Chef</h1>

![alt text](https://github.com/ngimb64/LFI-Chef/blob/main/LFI_Chef.png?raw=true)<br>
&#9745;&#65039; Bandit verified &nbsp;|&nbsp; &#9745;&#65039; Synk verified &nbsp;|&nbsp; &#9745;&#65039; Pylint verified 9.92/10
<br><br>
</div>

## **Notice**
> This tool may be used for legal purposes only.<br>
> Users take full responsibility for any actions performed using this tool.<br>
> The author accepts no liability for damage caused by this tool.<br>
> If these terms are not acceptable to you, then do not use this tool.

## Purpose
LFI Chef is a tool for parsing and sanitizing LFI wordlists and providing a means of generating
numerous mutations based on the levels/modes specified. For example, it can take a wordlist of 5,000
Windows paths in native format and generate up to over half a million mutations featuring WAF
evasion techniques. The screenshot example below demonstrates its capabilities:<br>
![alt text](https://github.com/ngimb64/LFI-Chef/blob/main/LFI_Chef_Result.png)

## Features

- LFI wordlist sanitization and generation
- Supports Windows and Linux based file systems
- Encoding evasion techniques
  - URL encoding => u
  - Double URL encoding => d
  - 16-bit unicode => b
  - Overlong UTF-8 encoding => o
- Directory traversals (default set with custom option)
- Null byte injection
  - Prepend => p
  - Append => a
  - Both => b

### License
The program is licensed under [GNU Public License v3.0](LICENSE.md)

### Contributions or Issues
[CONTRIBUTING](CONTRIBUTING.md)

## Installation
Start by running the venv and packages installation script:<br>
    `python3 setup.py venv`

Once installed, the venv can be activated from project root with:<br>
- Linux & Mac: `cd venv/bin; source activate; cd ../..`
- Windows: `cd venv\Scripts && ./activate && cd ../..`

## Usage
usage:
```
lfi_chef.py [-h] [--encoding ENCODING] [--traversal TRAVERSAL] [--traversal_chars TRAVERSAL_CHARS]
                 [--null_byte NULL_BYTE] [--out_file OUT_FILE] [--drive DRIVE]
                 in_file {generate,sanitize} {mac,linux,windows}
```
LFI Chef is a tool that helps automate the process of LFI wordlist generation with integrated evasion techniques

positional arguments:<br>
```
  in_file               The path to input file or name of file if in same directory
  {generate,sanitize}   The programs mode of operation
  {mac,linux,windows}   The OS of the LFI wordlist to generate

options:
  -h, --help            show this help message and exit
  --encoding ENCODING   Specify the encodings to use with path generation. u => url-encoding, d => double url-encoding, b =>
                        16-bit unicode, o => overlong utf-8 encoding. Example: udbo OR duo OR ou .. in any order/combo
  --traversal TRAVERSAL
                        Specify the number of recursions to generate directory traversal payloads or specify specificranges like
                        2:4 generating recursions 2-4
  --traversal_chars TRAVERSAL_CHARS
                        Specify the custom traversal payload chars that override default char set in a comma-separated with a
                        colon delimiter between traversal and slash format list like ../:/, ....//://, ..\:\, etc
  --null_byte NULL_BYTE
                        Generate null byte payloads based on generated encoding & traversal mutations. Features 3 modes: p
                        (prepend), a (append), b (both)
  --out_file OUT_FILE   The path where the output file is written or name of file if in same directory
  --drive DRIVE         The Windows drive associated with sanitization mode. If drive letter specified (Ex: A .. A-Z available),
                        itwill be parsed at the beginning of path unless it already exists. If not specified it will strip any
                        drive letters detected
```

## Usage Examples

Sanitizing a messy Windows path wordlist without a drive letter:<br>
`python3 lfi_chef.py <input_file> sanitize windows`

Sanitizing a messy Windows path wordlist with a drive letter:<br>
`python3 lfi_chef.py --drive <drive_letter> <input_file> sanitize windows`

Generating Windows wordlist with all encoding evasions, path traversal<br>
recursion set to 5, and null bytes both prepended and appended:<br>
`python3 lfi_chef.py --encoding udbo --traversal 5 --null_byte b <input_file> generate windows`

Generating Linux with url & double url encoding, path traversal recursion set to 5 with custom<br>
character set, and null bytes appended with a specified output file:<br>
`python3 lfi_chef.py --encoding ud --traversal 5 --traversal_chars '../:/,....//://' --null_byte a --out_file <output_file> <input_file> generate linux`