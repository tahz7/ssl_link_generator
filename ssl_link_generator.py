#!/usr/bin/python

import subprocess
import re
import sys
from collections import defaultdict
import os
from optparse import OptionParser
import datetime
import errno
from tempfile import NamedTemporaryFile
import itertools


def optionparse_args():

    help_list = '''\n  Options:
      -h, --help            show this help message and exit

      --cert          Path to where you'd like to store certificate
                      Default Path: /etc/pki/tls/certs
      --key           Path to where you'd like to store key
                      Default Path: /etc/pki/tls/private
      --ca            Path to where you'd like to store CA
                      Default Path: /etc/pki/tls/certs'

      --http          Choose whether to generate SSL link for either 
                      'apache' or 'nginx'
                      By Default the script automatically detects which 
                      is running'''

    parser = OptionParser(
        usage=help_list, conflict_handler="resolve", add_help_option=False)

    # time options group
    parser.add_option('-c', '--cert', help="Path to where you'd like to "
                                           "store certificate",
                      type='str', nargs=1)
    parser.add_option('-k', '--key', help="Path to where you'd like to "
                                          "store key",
                      type='str', nargs=1)
    parser.add_option('-c', '--ca', help="Path to where you'd like to "
                                         "store CA",
                      type='str', nargs=1)
    parser.add_option('-h', '--http', help="Choose whether to generate SSL "
                                           "link for either 'apache' "
                                           "or 'nginx'",
                      type='str', nargs=1)

    (options, args) = parser.parse_args()

    if options.http:
        options.http = options.http.lower()
        if options.http not in ['apache', 'nginx']:
            parser.error(
                'The --httpd option takes the following arguments; '
                'apache, nginx')

    return options


# get webserver to generate ssl links for
def get_httpd():
    httpd_list = set()
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]

    for pid in pids:
        try:
            if os.path.exists('/proc/{0}/exe'.format(pid)):
                processes = os.readlink('/proc/{0}/exe'.format(pid))
                regex_process = re.search("(httpd|nginx|apache2)+", processes)
                if regex_process is not None:
                    httpd_list.add(regex_process.group(1))
        except IOError:
            continue

    sys.stdin = open('/dev/tty')
    
    if not httpd_list:
        httpd_type = raw_input("Neither nginx or apache detected, please "
                               "choose which one you'd like to generate ssl "
                               "files for... \n")
    elif len(httpd_list) > 1:
        httpd_type = raw_input("Both nginx and apache detected, please "
                               "choose which one you'd like to generate "
                               "SSL files for... \n")
    else:
        httpd_type = list(httpd_list)[0]

    while True:
        if httpd_type not in ['httpd', 'nginx', 'apache2', 'apache']:
            httpd_type = raw_input("Could not recognize input. Please "
                                   "choose either 'apache' or 'nginx'... \n")
        else:
            break
    
    # plesk isn't supported
    if os.path.exists('/etc/psa'):
        print 'Warning: Plesk is installed on this server.'

    return httpd_type


class col:
    BLUE = '\033[94m'
    RED = '\033[31m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    PURPLE = '\033[35m'
    ORANGE = '\033[33m'
    LIGHTRED = '\033[91m'
    CYAN = '\033[36m'
    PINK = '\033[95m'
    HEADER = '\033[95m'
    BOLD = '\033[01m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'


class SSLValidate:
    def __init__(self):
        self.new_domain = defaultdict(self.domain_record)

    def domain_record(self):
        return {
            'cert': '',
            'key': '',
            'ca': '',
            'exp_date': ''
        }

    # get cert/key/ca from user
    def get_domain(self):
        domain_no = int(raw_input('How many domains do y'
                                  'ou wish to install SSL for?: '))

        for num in range(1, domain_no + 1):
            print ('Please copy and paste Certificate {0} (Press Enter once '
                   'you finish): \n'.format(col.ORANGE + str(num) + col.ENDC))
            cert_input = self.ssl_text_input()
            print ('Please copy and paste Key {0} (Press Enter once '
                   'you finish): \n'.format(col.ORANGE + str(num) + col.ENDC))
            key_input = self.ssl_text_input()
            print ('Please copy and paste CA Bundle {0} (Press Enter once '
                   'you finish): \n'.format(col.ORANGE + str(num) + col.ENDC))
            ca_input = self.ssl_text_input()

            cn_domain, reg_expire_date, alt_domain = self.validate_ssl(
                cert_input, ca_input, key_input)

            self.new_domain[cn_domain]['cert'] = cert_input
            self.new_domain[cn_domain]['key'] = key_input
            self.new_domain[cn_domain]['ca'] = ca_input
            self.new_domain[cn_domain]['exp_date'] = reg_expire_date

            if alt_domain:
                self.new_domain[cn_domain].setdefault('alt_domain', alt_domain)

        return self.new_domain

    # validates and retrieves common name, expire date, 
    # alternative domains.
    def validate_ssl(self, cert, ca, key, alt_domain=None):
        # get cert information
        cert_pipe_output = subprocess.Popen(
            ['openssl', 'x509', '-text'], stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, bufsize=1)
        cert_info = cert_pipe_output.communicate(cert)[0].strip()

        for line in iter(cert_info.splitlines()):
            regex_cn = re.search(r'(?=.*Subject)(?=.*CN=(.+?)$)', line)
            regex_expire_date = re.search(r'(?=.*Not After)(?=.*([a-zA-Z]{3}'
                                          r'\s+[0-9]{1,2} .+?) [a-zA-Z]+$)', 
                                          line)
            regex_alt_domain = re.search(r'DNS:', line)
            if regex_cn:
                cn = regex_cn.group(1)
            if regex_expire_date:
                expire_date = regex_expire_date.group(1)
            if regex_alt_domain:
                alt_domain = re.sub(r'(DNS|:|\s)', '', line).split(',')
                # remove duplication of cn also being in alt domain
                if cn in alt_domain:
                    alt_domain.remove(cn)

        # validate ca
        self.ca_validation(cert, ca, cn)
        # check if cert/key matches
        self.ssl_match(cert, key, cn)

        return cn, expire_date, alt_domain

    # validate ca bundle
    def ca_validation(self, cert, ca, cn):
        # create temp files in order to run subprocess openssl on it
        cert_temp = NamedTemporaryFile(delete=True)
        ca_temp = NamedTemporaryFile(delete=True)

        with cert_temp, ca_temp:
            cert_temp.write(cert)
            ca_temp.write(ca)
            cert_temp.flush()
            ca_temp.flush()
            # bash command to verify ca bundle
            ca_verify_cmd = subprocess.Popen(['openssl', 'verify', '-CAfile', 
                                              ca_temp.name, cert_temp.name],
                                             stdin=subprocess.PIPE, 
                                             stdout=subprocess.PIPE, bufsize=1)
            ca_verify_cmd.wait()
            ca_verify_cmd_output = ca_verify_cmd.communicate()[0].strip()

        regex_ca = re.search(
            "(Thawte|Symantec|Comodo|DigiCert|Entrust|GeoTrust|GoDaddy)", 
            ca_verify_cmd_output, re.IGNORECASE)

        # if there's no match, it means ca is incompatible with certificate
        if regex_ca:
            self.new_domain[cn]['ca_auth'] = regex_ca.group()

    # check if the cert/key matches
    def ssl_match(self, cert, key, cn):
        cert_comm = 'openssl x509 -noout -modulus'
        ca_comm = 'openssl rsa -noout -modulus'
        match = set()

        for ssl, comm in itertools.izip([cert, key], [cert_comm, ca_comm]):
            # get the md5 hash from both key/cert
            # same as doing this in bash eg. 'comm | openssl md5'
            md5_hash_output = subprocess.Popen(comm, stdin=subprocess.PIPE,
                                               stdout=subprocess.PIPE, 
                                               bufsize=1, shell=True)
            md5_hash_output.wait()
            md5_hash_pipe = md5_hash_output.communicate(ssl)[0].strip()
            md5_output = subprocess.Popen(['openssl', 'md5'], 
                                          stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE, bufsize=1)
            md5_output.wait()
            md5_pipe = md5_output.communicate(md5_hash_pipe)[0].strip()
            match.add(md5_pipe)

        # if md5 hashes match, there should only be one item in match set.
        # else cert/key does not match
        if len(match) < 2:
            self.new_domain[cn]['ssl_match'] = True

    def ssl_text_input(self, ssl_input='', break_word=''):
        while True:
            line = raw_input()
            if line.strip() == break_word:
                break
            ssl_input += "{0}\n".format(line)

        return ssl_input.strip()


class DisplaySSL:
    def __init__(self, domain, httpd_type, cmd_args):
        self.domain = domain
        self.httpd_type = httpd_type
        self.cmd_args = cmd_args

    # check if cert/ca and key dir exist, otherwise create
    def create_directory(self):
        cert_dir = '/etc/pki/tls/certs'
        key_dir = '/etc/pki/tls/private'
        ca_dir = cert_dir

        if self.cmd_args.cert:
            cert_dir = self.cmd_args.cert
        if self.cmd_args.key:
            key_dir = self.cmd_args.key
        if self.cmd_args.ca:
            ca_dir = self.cmd_args.ca

        for directory in [cert_dir, key_dir, ca_dir]:
            try:
                os.makedirs(directory)
            except OSError as exception:
                if exception.errno != errno.EEXIST:
                    print ('There was a problem creating the the '
                           'directory {0}'.format(directory))
        
        cert_dir = os.path.abspath(cert_dir)
        key_dir = os.path.abspath(key_dir)
        ca_dir = os.path.abspath(ca_dir)

        return cert_dir, key_dir, ca_dir

    # create the files for cert, key and ca bundle
    def create_ssl_file(self, cn, ssl_texts, ssl_types, directories):
        # if wildcard cn, then remove * for easier file naming
        if '*.' in cn:
            cn = re.sub(r'(\*\.)', '', cn)

        year = str(datetime.datetime.now().year)
        ssl_path = []

        # create files
        for text, extension, dir_link in itertools.izip(ssl_texts, ssl_types, 
                                                        directories):
            filename = os.path.join(dir_link, '{0}-{1}.{2}'.format(cn, year, 
                                                                   extension))

            while True:
                # if nginx is enabled, then the cert/ca is in one file.
                if extension == 'ca' and self.httpd_type == 'nginx':
                    filename = os.path.join(dir_link, '{0}-{1}.crt'.format(
                        cn, year))
                    break
                # if file exists, then rename it as a backup
                if os.path.isfile(filename):
                    for i in range(100):
                        rename_file = filename + '.bak{0}'.format(str(i))
                        if not os.path.isfile(rename_file):
                            os.rename(filename, rename_file)
                            break
                break

            with open(filename, 'ab') as temp_file:
                temp_file.write(text + '\n')
            # for private key, ensure permissions are 600
            if extension == 'key':
                os.chmod(filename, 0600)

            ssl_path.append(filename)

        return ssl_path

    def print_domains(self):
        print '\nWeb Server: {0}\n'.format(col.PURPLE + str(self.httpd_type) 
                                           + col.ENDC)
        directories = list(self.create_directory())

        for domain_key, domain_value in self.domain.iteritems():
            days_diff = self.get_day_diff(domain_value['exp_date'])

            # print certificate information
            print '-----------------------------------------------\n'
            print 'Common Name: {0}'.format(col.GREEN + domain_key + col.ENDC)

            # print alt domains (if exist)
            if 'alt_domain' in domain_value:
                print 'Alternative Domain(s): ',
                for domain in domain_value['alt_domain']:
                    print '{0} '.format(col.GREEN + domain + col.ENDC),
                print '\n'

            # print expire, ca and ssl match status
            expire_status = ('Expires in roughly {0} days'.format(col.YELLOW 
                             + str(days_diff) + col.ENDC) if days_diff > 0 
                             else col.RED + 'Expired' + col.ENDC)
            
            ca_status = (col.YELLOW + domain_value['ca_auth'] + col.ENDC
                         if 'ca_auth' in domain_value else 
                         col.RED + 'CA does not match Certificate' + col.ENDC)

            print ('Expiration Date: {0} '
                   '({1})'.format(col.YELLOW + domain_value['exp_date'] 
                                  + col.ENDC, expire_status))
            print 'Certificate Authority: {0}'.format(ca_status)

            if 'ssl_match' not in domain_value:
                print 'SSL Status: {0}'.format(col.RED + 'Cert and Key does '
                                               'not match' + col.ENDC)

            print
            
            # if all is well, create ssl files and print links.
            if 'ca_auth' in domain_value and 'ssl_match' in domain_value and (
                        days_diff > 0):
                ssl_texts = [domain_value['cert'], domain_value['key'], 
                             domain_value['ca']]
                ssl_types = ['crt', 'key', 'ca']
                ssl_path = self.create_ssl_file(domain_key, ssl_texts, 
                                                ssl_types, directories)
                print '===== COPY AND PASTE THE FOLLOWING IN VHOST ====\n'

                if self.httpd_type == 'nginx':
                    print col.CYAN + 'ssl_certificate ' + col.ENDC, ssl_path[0]
                    print (col.CYAN + 'ssl_certificate_key ' + col.ENDC, 
                           ssl_path[1])
                else:
                    # apache
                    print (col.CYAN + 'SSLEngine' + col.ENDC, col.RED + 'On'
                           + col.ENDC)
                    print (col.CYAN + 'SSLCertificateFile ' + col.ENDC, 
                           ssl_path[0])
                    print (col.CYAN + 'SSLCertificateKeyFile ' + col.ENDC, 
                           ssl_path[1])
                    print (col.CYAN + 'SSLCACertificateFile' + col.ENDC, 
                           ssl_path[2])

                print '\n\n'

    def get_day_diff(self, date):
        # get date difference for certificate expiration
        cert_exp_date_datetime = datetime.datetime.strptime(
            date, '%b %d %H:%M:%S %Y').date()
        current_date = datetime.datetime.now().date()
        date_diff = cert_exp_date_datetime - current_date
        days_dif = date_diff.days

        return days_dif


def main():
    sys.stdin = open('/dev/tty')
    cmd_args = optionparse_args()

    if cmd_args.http:
        httpd_type = cmd_args.http
    else:
        httpd_type = get_httpd()

    new_ssl = SSLValidate()
    domain = new_ssl.get_domain()

    DisplaySSL(domain, httpd_type, cmd_args).print_domains()

    sys.stdout.close()
    sys.stderr.close()


if __name__ == "__main__":
    main()
