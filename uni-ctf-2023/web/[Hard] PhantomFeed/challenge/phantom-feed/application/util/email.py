import re, smtplib, time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Work in progress

class EmailClient:
    def __init__(self, to_email):
        email_verified = self.parse_email(to_email)
        if email_verified:
            self.to_email = to_email
        else:
            self.to_email = "error message"
        self.smtp_server = "smtp.phantomfeed.htb"
        self.smtp_port = 587
        self.username = "lean@phantomfeed.htb"
        self.password = "HAQaM;Bk6V~^7]_!'-NwRT"


    def parse_email(self, email):
        pattern = r"^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@(([0-9a-zA-Z])+([-\w]*[0-9a-zA-Z])*\.)+[a-zA-Z]{2,9})$"

        try:
            match = re.match(pattern, email)

            if match:
                return True
            else:
                return False

        except Exception:
            return False


    def send_email(self, message):
        pass
        # try:
        #     self.server = smtplib.SMTP(self.smtp_server, self.smtp_port)
        #     self.server.starttls()  # Use TLS for security
        #     self.server.login(self.username, self.password)

        #     msg = MIMEMultipart()
        #     msg["From"] = self.username
        #     msg["To"] = to_email
        #     msg["Subject"] = "Verification code"

        #     msg.attach(MIMEText(message, "plain"))
        #     self.server.sendmail(self.username, to_email, msg.as_string())
        #     self.server.quit()
        # except Exception as e:
        #     print(e)