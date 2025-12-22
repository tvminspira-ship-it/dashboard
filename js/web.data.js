// /js/web.data.js
window.VM_DATA = window.VM_DATA || {};
window.VM_DATA.webTSV = String.raw`Application Name	Testing URL	Status 	Security observation	Critical	High	Medium	Low	Informational	Testing performed date	Revlidation Date	Vulnerability Reported Date 	Vulnerability Ageing	Owner
QMS BOT	https://qmsbot.adityabirlacapital.com/Link_External/#/otp-login	Closed	No Rate Limit			1			6/26/2025	7/29/2025	6/26/2025	175	Mahesh Kothari
		Closed	Malicious File Upload			1							
		Open	Improper Input Validation				1						
		Open	Application is Vulnerable to Breach Attack				1						
		Open	Application is Vulnerable to Clickjacking				1						
Sales Reel	https://abssl-preprod.sharpselltech.com/app/#/login/both 	Closed	Insufficient Rate Limiting on Like Action			1			5/28/2025	6/24/2025			Shankar Rsmamurthy
		Closed	Client-Side Interaction Without Validation			1							
		Closed	Data Exposure via Track API			1							
		Closed	Sensitive Information Disclosure			1							
		Closed	Cookie without HTTP Only Flag Set				1						
		Closed	Improper Input Validation				1						
		Closed	Application Vulnerable to Lucky 13 Attack				1						
		Closed	Admin OTP Leak via Request Manipulation				1						
ABC Samiksha 	https://abc-samiksha.adityabirlacapital.com/Authentication/Login.aspx 	Open	Server Information Disclosure				1		6/13/2025		6/13/2025	188	
		Open	Outdated JQuery Version Detected				1						
		Open	Prototype Pollution Vulnerability				1						
		Open	Application Vulnerable to Beast Attack				1						
		Open	Application Vulnerable to Lucky 13 Attack				1						
		Open	Sensititve HTTP Methods Disclosed				1						
		Open	Misconfigured HTTP Headers				1						
Laser UAT	https://uatlars.insideabc.com/login.aspx	Closed	Missing Security Headers				1		7/7/2025	8/1/2025			Sugan Jayaraman
		Closed	Application Vulnerable to Beast Attack				1						
		Closed	Application Vulnerable to Lucky 13 Attack				1						
		Closed	Application Vulnerable to Sweet 32				1						
		Closed	Missing CAPTCHA				1						
		Closed	Deprecated Version of JavaScript Library				1						
		Closed	Lack of Session Management for Concurrent Logins				1						
		Closed	Server Information Disclosure Through Banners				1						
CCM UAT	https://10.91.6.46/login 	Closed	Sensitive Data Exposure		1				7/10/2025	7/23/2025			Sugan Jayaraman
		Closed	Unauthorized Access to Admin Dashboard 			1							
		Closed	Missing Security Headers				1						
		Closed	Application Vulnerable to Clickjacking				1						
		Closed	Application Vulnerable to Lucky 13 Attack				1						
		Closed	Broken Authentication- Token Reuse and Missing Validation				1						
		Closed	Missing CAPTCHA				1						
		Closed	Deprecated Version of Angular Library				1						
		Closed	Lack of Session Management for Concurrent Logins				1						
		Closed	Server Information Disclosure Through Banners				1						
Stellar UAT	https://stellar.abcscuat.com	Closed	Missing Security Headers				1		7/22/2025	7/30/2025			Avinash Shukla
		Closed	Application Vulnerable to Clickjacking				1						
		Closed	Application Vulnerable to Breach Attack				1						
		Closed	Sensitive Information Disclosure				1						
Pay Invoice	https://payinvoiceuat.insideabc.com/buyer_abcl/#/login	Open	Vulnerable Server in Use			1			7/28/2025		7/28/2025	143	Sanjeev Singh
		Open	Sensitive Information Disclosure			1							
		Open	Missing Security Headers				1						
		Open	Application Vulnerable to Clickjacking				1						
		Open	Concurrent Login Allowed				1						
		Open	Forgot Password Page Without Captcha				1						
		Open	Usage of Vulnerable and Outdated Bootstrap Version 4.5.0				1						
		Open	Use of Weak Algorithm (HS256) for JWT Token				1						
		Open	Improper Input Validation				1						
		Open	Malicious File Upload				1						
		Open	Improper Session Key Validation				1						
		Open	Session Token Reuse After Logout				1						
		Open	Options Method Enabled					1					
		Open	Usage of Outdated Components in Use					1					
Sharpsell	https://abc.sharpselltech.com/app/	Closed	CSP Header Misconfigured				1		8/9/2025	8/21/2025			
		Closed	Improper Input Validation				1						
		Closed	Application Vulnerable to Beast Attack				1						
		Closed	Appication Vulnerable to Lucky 13 Attack				1						
		Closed	Server Version Disclosure Through Banners					1					
ICAT UAT	https://icatuat.insideabc.com	Open	Missing Security Headers				1		8/14/2025		8/14/2025	126	Sugan Jayaraman
		Open	Application Vulnerable to Beast Attack				1						
		Open	Application Vulnerable to Lucky 13 Attack				1						
		Open	Application Vulnerable to Sweet 32				1						
		Open	Missing CAPTCHA				1						
		Open	Application Vulnerable to Clickjacking				1						
		Open	Insecure Cross-Origin Resource Sharing (CORS)				1						
		Open	Options Method Enabled				1						
		Open	Server Version Disclosure Through Banners				1						
ABC Mentoring Program 	https://adityabirlacapital.sharepoint.com/sites/MentoringPortalDev 	Open	Host Header Injection			1			8/22/2025		8/22/2025	118	
		Open	Missing Security Headers				1						
		Open	Application is Vulnerable to Lucky 13 Attack				1						
		Open	Deprecated Version of JavaScript Library				1						
		Open	Server Information Disclosure Through Banners				1						
OneConnectDev	https://adityabirlacapital.sharepoint.com/sites/OneconnectDev	Open	Missing Security Headers				1		9/19/2025		9/19/2025	90	
		Open	Application is Vulnerable to Lucky 13 Attack				1						
		Open	Deprecated Version of JavaScript Library				1						
		Open	Server Information Disclosure Through Banners				1						`;
