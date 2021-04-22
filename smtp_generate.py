'''
smtp_generate.py
this code converts an AWS secret access key to an Amazon SES Classic SMTP password

To obtain your SMTP password by using this script, save the preceding code as smtp_credentials_generate.py. Then, at the command line, execute the following command:

python path/to/smtp_credentials_generate.py wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY us-east-1
In the preceding command, do the following:

Replace path/to/ with the path to the location where you saved smtp_credentials_generate.py.
Replace wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY with the secret access key that you want to convert into an SMTP password.
Replace us-east-1 with the AWS Region in which you want to use the SMTP credentials.
When this script runs successfully, the only output is your SMTP password.

more details can be found here:
https://docs.aws.amazon.com/ses/latest/DeveloperGuide/smtp-credentials.html

'''
#!/usr/bin/env python3

import hmac
import hashlib
import base64
import argparse

SMTP_REGIONS = [
    'us-east-2',       # US East (Ohio)
    'us-east-1',       # US East (N. Virginia)
    'us-west-2',       # US West (Oregon)
    'ap-south-1',      # Asia Pacific (Mumbai)
    'ap-northeast-2',  # Asia Pacific (Seoul)
    'ap-southeast-1',  # Asia Pacific (Singapore)
    'ap-southeast-2',  # Asia Pacific (Sydney)
    'ap-northeast-1',  # Asia Pacific (Tokyo)
    'ca-central-1',    # Canada (Central)
    'eu-central-1',    # Europe (Frankfurt)
    'eu-west-1',       # Europe (Ireland)
    'eu-west-2',       # Europe (London)
    'sa-east-1',       # South America (Sao Paulo)
    'us-gov-west-1',   # AWS GovCloud (US)
]

# These values are required to calculate the signature. Do not change them.
DATE = "11111111"
SERVICE = "ses"
MESSAGE = "SendRawEmail"
TERMINAL = "aws4_request"
VERSION = 0x04


def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def calculate_key(secret_access_key, region):
    if region not in SMTP_REGIONS:
        raise ValueError(f"The {region} Region doesn't have an SMTP endpoint.")

    signature = sign(("AWS4" + secret_access_key).encode('utf-8'), DATE)
    signature = sign(signature, region)
    signature = sign(signature, SERVICE)
    signature = sign(signature, TERMINAL)
    signature = sign(signature, MESSAGE)
    signature_and_version = bytes([VERSION]) + signature
    smtp_password = base64.b64encode(signature_and_version)
    return smtp_password.decode('utf-8')


def main():
    parser = argparse.ArgumentParser(
        description='Convert a Secret Access Key for an IAM user to an SMTP password.')
    parser.add_argument(
        'secret', help='The Secret Access Key to convert.')
    parser.add_argument(
        'region',
        help='The AWS Region where the SMTP password will be used.',
        choices=SMTP_REGIONS)
    args = parser.parse_args()
    print(calculate_key(args.secret, args.region))


if __name__ == '__main__':
    main()
