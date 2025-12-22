window.VM_DATA = window.VM_DATA || {};
window.VM_DATA.apiTSV = `Application Name	Testing URL	Status 	Security observation	Critical	High	Medium	Low	Informational	Testing performed date	Closing Date	Vulnerability Reported Date	Vulnerability Ageing	Owner
api.abcscuat.com (10)	https://api.abcscuat.com/	Closed	Broken Authentication		1				6/17/2025		6/17/2025	184	Hrithik Bhamre
		Closed	Potential XSS			1							
		Closed	Insecure Direct Object Reference			1							
		Closed	Insufficient Anti-automation/ Missing Rate Limit			1							
		Closed	Cross Origin Resource Sharing			1							
		Open	Improper Input Validation				1						
		Closed	Missing Security Headers				1						
SERVICE APPLICATION (2)	https://api.abcscuat.com/servicingapp 	Closed	Missing Security Headers				1		6/27/2025		6/27/2025		Hrithik Bhamre
PARTNER PORTAL (2)	https://partnerconnect.insideabc.com	Closed	API potentially vulnerable to SQL Injection			1			7/29/2025		7/29/2025	142	Sanjeev Singh
		Closed	Error Disclosing Database Queries			1							
		Open	Accepting Invalid GST Number				1						
		Open	Missing Rate Limit				1						
		Open	Missing Security Headers				1						
SFDC UNFYD ABHFL (3)	https://api.abcscuat.com/sfdc-abhfl/unfyd	Closed	Missing Security Headers				1		9/1/2025	9/5/2025			Hrithik Bhamre
 SALESFORCE LMS	https://api.abcscuat.com/abccs/teradata/getlipolicyinfo	Closed	Missing Security Headers				1		9/10/2025	9/16/2025			Kaustubh Pawar
		Closed	Imroper Error Handling				1						
ABC LEARNING API(2)	https://abclearning.adityabirlacapital.com/webservice 	Closed	Missing Security Headers				1		9/23/2025	10/17/2025			Rupesh Shirke
		Closed	Server Information Disclosure Through Banners				1						
		Closed	Misconfigured Access-Control-Allow-Origin-Header				1						
SFDC LMS (8)	https://api.abcscuat.com/lms-abcl	Open	No Rate Limit				1		10/16/2025	10/17/2025	10/16/2025		Hrithik Bhamre
SHARPSELL (11)	https://abc.sharpselltech.com/convergence/v2/getMagicUrl	Open	No Rate Limit				1		10/14/2025		10/14/2025	65	Rupesh Shirke
ESB Modernization DWH (24)	https://api.abcscuat.com/dwh/v1//dwh	Open	Insecure Direct Object Reference	1					10/23/2025		10/23/2025	56	Vaibhav Mishra
		Open	Insufficient Anti-automation/ Missing Rate Limit				1						
		Open	Cross-Site Scripting (XSS) Filter Disabled				1						
		Open	Misconfigured Access-Control-Allow-Origin-Header				1						
		Open	Misconfigured CSP Header				1						
Tiny URL (5)	https://api.abcscuat.com/tinyurl	Open	Acceptance of expired authentication tokens			1			10/24/2025		10/24/2025	55	Vaibhav Mishra
		Open	Missing authentication token accepted			1							
		Open	Unverified Token Signature			1							
		Open	Missing Security Headers				1						
		Open	Improper Input Validation				1						
UAT Inbound (7)	https://api.abcscuat.com/crm-abfl/ 	Open	No Rate Limit			1			11/7/2025		11/13/2025	35	Hrithik Bhamre
		Open	IDOR			1							
UAT Outbound (9)	"https://api.abcscuat.com/crm-abfl/basiccustomerinfo 
https://api.abcscuat.com/crm-abfl/gccpropertydetails
https://api.abcscuat.com/crm-abfl/rtlrealtimeinstallpdtls
https://api.abcscuat.com/crm-abfl/rtlrealtimeloandetails
https://api.abcscuat.com/crm-abfl/rtlrealtimeloanmis
https://api.abcscuat.com/crm-abfl/odpeventoutcome?count=1&expand=false
https://api.abcscuat.com/crm-abfl/loanutilizationdetails
https://api.abcscuat.com/crm-abfl/getlmsdatadwh
https://api.abcscuat.com/crm-abfl/disbursementdetails"	Open	No Rate Limit			1			11/3/2025		11/13/2025	35	Hrithik Bhamre
		Open	Missing Security Headers				1						`;
