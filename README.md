
# subJS

`subJS` is a Python script designed for bug bounty hunters and security researchers. It scans a list of subdomains to find and categorize JavaScript files and gather technology stack information using the `builtwith` library. The script supports parallel processing for efficient scanning and can log the results to a file.

## Features

- **JavaScript File Discovery**: Finds internal and external JavaScript files on subdomains.
- **Technology Stack Detection**: Uses `builtwith` to detect technologies used by the subdomains.
- **Parallel Processing**: Scans multiple subdomains simultaneously for faster results.
- **Error Handling**: Skips subdomains that cannot be reached or do not contain JavaScript files.
- **Logging**: Saves the results to a specified log file.

## Requirements

- Python 3.x
- `requests`
- `beautifulsoup4`
- `colorama`
- `tenacity`
- `builtwith`

## Installation

1. Clone this repository or download the script.

2. Install the required libraries:
    ```bash
    pip install requests beautifulsoup4 colorama tenacity builtwith
    ```

## Usage

### Scan a Single Domain

To scan a single domain and save the output to a file:
```bash
python3 subJS.py --domain=example.com --output=output.txt
```

### Scan Subdomains from a File

To scan subdomains listed in a file and save the output to a file:
```bash
python3 subJS.py --file=subdomains.txt --output=output.txt
```

### Command-Line Arguments

- `--domain`: Specify a single domain to check.
- `--file`: Specify a file containing a list of subdomains to check. Default is `subdomains.txt`.
- `--output`: Specify a file to save the output.

## Example Output

The script will output the found JavaScript files and technology stack information for each subdomain that is successfully scanned.

### Console Output

```
Technologies used by www.example.com:
web-servers: Apache
font-scripts: Google Font API
tag-managers: Google Tag Manager
web-frameworks: Twitter Bootstrap
javascript-frameworks: jQuery

Internal JavaScript files found in www.example.com:
/etc.clientlibs/clientlibs/granite/jquery.min.js
/etc.clientlibs/clientlibs/granite/utils.min.js

External JavaScript files found in www.example.com:
//assets.adobedtm.com/6422e0f550a2/017d80491d7e/launch-e08352bc3db4.min.js
```

### Log File Output

The log file will contain the same information with timestamps for each entry.

```
2024-05-25 14:23:12 - Technologies used by www.example.com:
2024-05-25 14:23:12 - web-servers: Apache
2024-05-25 14:23:12 - font-scripts: Google Font API
2024-05-25 14:23:12 - tag-managers: Google Tag Manager
2024-05-25 14:23:12 - web-frameworks: Twitter Bootstrap
2024-05-25 14:23:12 - javascript-frameworks: jQuery
2024-05-25 14:23:12 - Internal JavaScript files found in www.example.com:
/etc.clientlibs/clientlibs/granite/jquery.min.js
/etc.clientlibs/clientlibs/granite/utils.min.js
2024-05-25 14:23:12 - External JavaScript files found in www.example.com:
//assets.adobedtm.com/6422e0f550a2/017d80491d7e/launch-e08352bc3db4.min.js
```
