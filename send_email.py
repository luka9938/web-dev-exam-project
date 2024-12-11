import smtplib, ssl
from bottle import request
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_verification_email(receiver_email, verification_code):
    sender_email = 'joeybidenisbased@gmail.com'
    password = 'tdvi euik qgsa bzdf'

    base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}/"

    message = MIMEMultipart("alternative")
    message["Subject"] = "Verify your email address"
    message["From"] = sender_email
    message["To"] = receiver_email


    text = f"""\
    Hi,
    Please verify your email address by using the following code: {verification_code}
    """
    html = f"""\
    <html>
      <body>
        <p>Hi,<br>
          Please verify your email by clicking the link below:<br>
          <a href="{base_url}verify?code={verification_code}">Verify Email</a>
        </p>
      </body>
    </html>
    """

    # Turn these into plain/html MIMEText objects
    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    # Add HTML/plain-text parts to MIMEMultipart message
    # The email client will try to render the last part first
    message.attach(part1)
    message.attach(part2)

    # Create secure connection with server and send email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())