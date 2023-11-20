import ssl
import socket
import datetime
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from config import domains, receiver_email, sender_email, password_google


logging.basicConfig(filename='error.log', level=logging.ERROR)

def send_email(domain_info):
    smtp_server = "smtp.gmail.com"
    smtp_port_ssl = 465
    context = ssl.create_default_context(cafile="./ca-certificates.crt")

    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = receiver_email

    email_content = "<html><body><h2>Domains Validity Information</h2><table border='1'><tr><th>Domain</th><th>SSL Days Left</th><th>WHOIS Days Left</th></tr>"

    for domain, info in domain_info.items():
        email_content += f"<tr><td>{domain}</td><td>{info['ssl_days_left']}</td><td>{info['whois_days_left']}</td></tr>"
        if (info.get('ssl_days_left') is not None and info['ssl_days_left'] <= 7) or (info.get('whois_days_left') is not None and info['whois_days_left'] <= 7):
            message['Subject'] = "WARNING! The expiration date of some SSL certificate or domain expires in 7 days or less!"
            break
    else:
        message['Subject'] = "All good! The expiration date of all SSL certificates and domains is longer than 7 days!"

    email_content += "</table></body></html>"

    try:
        message.attach(MIMEText(email_content, 'html')) 
        server = smtplib.SMTP_SSL(smtp_server, smtp_port_ssl, context=context)
        server.login(sender_email, password_google)
        server.sendmail(sender_email, receiver_email, message.as_string())
        print("Email sent successfully!")
    except smtplib.SMTPConnectError as connect_error:
        print(f"Failed to connect to the SMTP server. Error: {connect_error}")
    except smtplib.SMTPAuthenticationError as auth_error:
        print(f"SMTP server authentication failed. Error: {auth_error}")
    except smtplib.SMTPException as smtp_error:
        print(f"SMTP server error occurred. Error: {smtp_error}")
    except Exception as e:
        print(f"Failed to send email. Error: {e}")
    finally:
        if 'server' in locals():
            server.quit()



def get_certificate_expiration(domain):
    context = ssl.create_default_context(cafile="./ca-certificates.crt")
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    conn.settimeout(10) 
    try:
        conn.connect((domain, 443))
        certificate = conn.getpeercert()

        if 'notAfter' in certificate:
            expiration_date = datetime.datetime.strptime(certificate['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_until_expire = (expiration_date - datetime.datetime.utcnow()).days
            return expiration_date, days_until_expire
        else:
            return None, None
    except ssl.SSLError as e:
        logging.error(f"SSL Error: {e}")
        return None, None
    except socket.error as e:
        logging.error(f"Socket Error: {e}")
        return None, None
    finally:
        conn.close()

def get_domain_expiration(domain):
    try:
        whois_server = 'whois.dns.pl'
        port = 43  
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((whois_server, port))
            s.sendall((domain + "\r\n").encode())  
            response = b""
            expiration_date = None

            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data

            whois_info = response.decode('utf-8')
            lines = whois_info.split('\n')
            for line in lines:
                if 'renewal date' in line.lower():
                    expiration_date = line.split(':', 1)[-1].strip()
                    expiration_date = expiration_date.replace('.', '-')
                    break
        
        days_until_expire = (datetime.datetime.strptime(expiration_date, "%Y-%m-%d %H:%M:%S") - datetime.datetime.utcnow()).days
        return expiration_date, days_until_expire
    except Exception as e:
        logging.error(f"Error retrieving WHOIS information: {e}")
        return None, None

domain_info = {} 

for domain in domains:
    ssl_expiration_date, ssl_days_left = get_certificate_expiration(domain)
    whois_expiration_date, whois_days_left = get_domain_expiration(domain)

    domain_info[domain] = {  
        "ssl_expiration_date": ssl_expiration_date,
        "ssl_days_left": ssl_days_left,
        "whois_expiration_date": whois_expiration_date,
        "whois_days_left": whois_days_left
    }


for domain, info in domain_info.items():
    print(f"Domain: {domain}")
    print(f"SSL certificate expires on: {info['ssl_expiration_date']}")
    print(f"Days until SSL expiration: {info['ssl_days_left']}")
    print(f"WHOIS expiration date is: {info['whois_expiration_date']}")
    print(f"Days until WHOIS expiration: {info['whois_days_left']}")

send_email(domain_info)
