import mailbox, email, re, base64, smtplib
import urllib.request
from email.mime.text import MIMEText
from datetime import datetime
#from pprint import pprint

#Declare some stuff
#RIPE IP WHOIS query link template
ripe = 'https://apps.db.ripe.net/search/query.html?searchtext={}'
eml_pattern = r'[a-zA-Z0-9\.]{1,64}@[a-zA-Z0-9\.-]{3,255}'
mbox = mailbox.mbox('test.mbox', create=False)
today = datetime.today().date()

#Returns a list of abuse contacts based on an IP list
def dig_abuse_eml(ips: list) -> list:
	abusers = []
	for ip in ips:
		ripe_src = urllib.request.urlopen(ripe.format(ip)).read().decode('utf-8')
		for row in ripe_src.split('\n'):
			if "Abuse contact info:" in row:
				abuser = re.search(eml_pattern, row)[0]
				if abuser not in abusers:
					abusers.append(abuser)
	return abusers

#Forward the report to the abusers
def fwd_to_abusers(eml: object, abusers: list, sender: str, subject: str):
	if eml.is_multipart():
		fwd = MIMEText('\n'.join(str(part) for part in eml.get_payload()))
	else:
		fwd = MIMEText(eml.get_payload())
	fwd['From'] = sender
	fwd['Subject'] = subject
	for addr in abusers:
		fwd['To'] = addr
		smtp = smtplib.SMTP('localhost')
		smtp.send_message(fwd)
		smtp.quit()
		del(fwd['To'])


def src_certbund(eml: object) -> list:
	pattern = r'^\"[0-9]{1,6}\",\"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
	for part in eml.walk():
		if part.get_content_type() == 'text/plain':
			return re.findall(pattern, part.get_payload(), re.M)


def src_dea_gov_de(eml: object) -> list:
	pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
	for part in eml.walk():
		if part.get_content_type() == 'application/octet-stream':
			return re.findall(pattern, base64.b64decode(part.get_payload()).decode('utf-8'))


def src_csirt_cz(eml: object) -> list:
	pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
	for part in eml.walk():
		if part.get_content_type() == 'application/octet-stream':
			return re.findall(pattern, base64.b64decode(part.get_payload()).decode('utf-8'))[1::2]


for i in range(len(mbox)):
	eml = mbox.get_message(i)
	eml_from = re.search(eml_pattern, eml['From'])[0]
	eml_date = datetime.strptime(eml['Date'], '%a, %d %b %Y %H:%M:%S %z').date()
	if eml_date == today:
		if eml_from == 'reports@reports.cert-bund.de':
			fwd_to_abusers(eml, dig_abuse_eml(src_certbund(eml)), eml_from, eml['Subject'])
		elif eml_from == 'incidents@dea.gov.ge':
			fwd_to_abusers(eml, dig_abuse_eml(src_dea_gov_de(eml)), eml_from, eml['Subject'])
		elif eml_from == 'abuse@csirt.cz':
			fwd_to_abusers(eml, dig_abuse_eml(src_csirt_cz(eml)), eml_from, eml['Subject'])






#	eml = email.message_from_string(mbox.get_message(i).as_string())
#print(part['Content-Disposition'])



#print(mbox[34])
#message = mbox[int(argv[1])]

#if message.is_multipart():
#	content = '\n'.join( str(part) for part in message.get_payload())
#else:
#	content = message.get_payload()

#print(content)
#print('---------------------')

#print(mbox[0].get_payload())
#print(mbox[0].get_payload(decode=True))


