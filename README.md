# burp-suite-token-fetcher
Burp Extender to add unique form tokens to scanner requests.

This extension will hit a form page, parse out a valid form token, and add this token to scanner requests. Use the Token Fetcher GUI tab to set the URL of the form page, and regular expressions for extracting and inserting the token. 

Settings required: 
* You must use a maximum of one thread for scanning. 
* Extender must be configured to use Burp cookie jar (in Session Handling Rules)
