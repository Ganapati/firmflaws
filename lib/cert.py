import os
from OpenSSL import crypto as c
from datetime import datetime

def is_cert(filename):
    """ check if file is a cert
    """
    
    filename, file_extension = os.path.splitext(filename)
    if file_extension in ['.cert', '.pem']:
        return True
    return False

def check_cert(filename):
    """ Check revocation date and bits
    """
    with open("./extracted/etc/server.pem", "r") as cert_file:
        response = []
        crt = c.load_certificate(c.FILETYPE_PEM, cert_file.read())
        end_date = crt.get_notAfter().decode("utf-8")[:-1]
        bits = crt.get_pubkey().bits()

        if bits < 1024:
            response.append("pubkey bits : %s" % bits)

        now = datetime.datetime.now()
        current = "%s%02d%02d%02d%02d%02d" % (now.year, 
                                              now.month, 
                                              now.day, 
                                              now.hour, 
                                              now.minute, 
                                              now.second)
        if int(current) > int(end_date):
            response.append("Certificate expired")
    return response