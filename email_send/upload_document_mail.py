import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from decouple import config



sender = config('EMAIL_SENDER')
password = config('EMAIL_PASSWORD')

def send_email(recipient: str, doc_id: int, documentTeamName: str, firstName: str):
    if recipient.__contains__("string"):
        print("This was a test user.")
        return
    
    message = MIMEMultipart()
    message['From'] = sender
    message['To'] = recipient
    message['Subject'] = f"{firstName} has invited you to {documentTeamName}"
    print("====================")
    # Read the HTML template file
    with open('email.html', 'r', encoding='utf-8') as file:
        html_template = file.read()
    # print("====================",html_template)
    # Replace placeholders in the HTML template
    html_content = html_template.replace('{Document Team Name}', documentTeamName).replace('{First NAME}', firstName).replace('{Document id}', str(doc_id))

    # Attach HTML content to the email
    message.attach(MIMEText(html_content, 'html'))

    # Create SMTP session for sending the mail
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
        smtp_server.login(sender, password)
        smtp_server.sendmail(sender, recipient, message.as_string())
    print("Message sent!")

