package burp;

import com.codemagi.burp.BaseExtender;
import com.monikamorrow.burp.BurpSuiteTab;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Burp Extender to add unique form tokens to scanner requests  
 * 
 * This extension will hit a form page, parse out a valid form token, and add this token to scanner requests. 
 * 
 * Settings required: 
 * <li>You must use a maximum of one thread for scanning. 
 * <li>Extender must be configured to use Burp cookie jar (in Session Handling Rules)
 * 
 * @author August Detlefsen <augustd at codemagi dot com>
 */
public class BurpExtender extends BaseExtender implements IHttpListener, IExtensionStateListener {

    private static final boolean DEBUG = true;
    
    protected GUIComponent guiPanel;
    protected BurpSuiteTab mTab;

    // pattern used to replace the form token with a fresh value on scanner requests
    private Pattern tokenInsertionPattern  = Pattern.compile(""); //name=\"FORM_TOKEN\"\\r\\n\\r\\n([A-Za-z0-9]*)
    
    // pattern used to parse out the token from the form page
    private Pattern tokenExtractionPattern = Pattern.compile(""); //<input type=\"hidden\" name=\"FORM_TOKEN\" value=\"([A-Za-z0-9]*)\"/>
    
    // the URL to the form page
    private URL formUrl = null;
    private String formUrlString = null; 
    
    @Override
    protected void initialize() {
        //set the extension Name
	extensionName = "Token Fetcher";

        //tell Burp we want to process HTTP requests
	callbacks.registerHttpListener(this);
        
        //init our GUI component
	guiPanel = new GUIComponent(this, callbacks);
        
        //add a tab to the Burp UI
        mTab = new BurpSuiteTab(extensionName, callbacks);
        mTab.addComponent(guiPanel);

        guiPanel.restoreSettings();
    }
    
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
	if (DEBUG) callbacks.printOutput("processHttpMessage:\n\n");
        if (DEBUG) callbacks.printOutput("tokenExtractionPattern: "+ tokenExtractionPattern);
	if (DEBUG) callbacks.printOutput("tokenInsertionPattern: " + tokenInsertionPattern);
        if (messageIsRequest && callbacks.TOOL_SCANNER == toolFlag) {
	    //see if the request contains a FORM_TOKEN
	    byte[] scannerRequest = messageInfo.getRequest();
	    String requestString = helpers.bytesToString(scannerRequest);//scannerRequest.toString();
	    if (DEBUG) callbacks.printOutput(requestString);
	    
	    Matcher matcher = tokenInsertionPattern.matcher(requestString);
	    if (matcher.find()) {
		if (DEBUG) callbacks.printOutput("\n\nRequest contains a token. Fetching fresh token from: " + formUrlString);
		//this request contains a token -fetch a fresh token from the configured page
		String token = getFreshToken();
		if (DEBUG) callbacks.printOutput("Token retrieved! " + token);
		
		if (token != null) {
		    //requestString = matcher.replaceAll("FORM_TOKEN=" + token);
                    requestString = replaceGroup(tokenInsertionPattern, requestString, 1, token);
                    
                    
		    //requestString = matcher.replaceAll("name=\"FORM_TOKEN\"\r\n\r\n" + token);
		    if (DEBUG) callbacks.printOutput("UPDATED REQUEST:\n\n" + requestString);
		}
	    }
	    
	    messageInfo.setRequest(requestString.getBytes());
	}
	
    }
    
    private String getFreshToken() {
        if (formUrl == null) {
            return null;
        }
        callbacks.printOutput("Fetching fresh token from: " + formUrl.toString());

        //construct request to hit the form page and extract a fresh token
        byte[] request = helpers.buildHttpRequest(formUrl);

        //actually make the request
        if (DEBUG) {
            callbacks.printOutput("Requesting token form:\n\n" + helpers.bytesToString(request));
        }
        byte[] response = callbacks.makeHttpRequest(formUrl.getHost(), 443, true, request);
        String responseString = helpers.bytesToString(response);
        if (DEBUG) {
            callbacks.printOutput("Token form response\n\n" + responseString);
        }

        Matcher matcher = tokenExtractionPattern.matcher(responseString);
        if (matcher.find()) {
            return matcher.group(1);
        }

        return null;
    }

    public static String replaceGroup(Pattern regex, String source, int groupToReplace, String replacement) {
        return replaceGroup(regex, source, groupToReplace, 1, replacement);
    }

    public static String replaceGroup(Pattern regex, String source, int groupToReplace, int groupOccurrence, String replacement) {
        Matcher m = regex.matcher(source);
        for (int i = 0; i < groupOccurrence; i++) {
            if (!m.find()) {
                return source; // pattern not met, may also throw an exception here
            }
        }
        return new StringBuilder(source)
                .replace(m.start(groupToReplace), m.end(groupToReplace), replacement)
                .toString();
    }

    public Pattern getTokenInsertionPattern() {
        return tokenInsertionPattern;
    }

    public void setTokenInsertionPattern(Pattern pattern) {
        this.tokenInsertionPattern = pattern;
    }

    public boolean setTokenInsertionPattern(String patternString) {
        try {
            Pattern pattern = Pattern.compile(patternString);
            setTokenInsertionPattern(pattern);
            return true;
        } catch (PatternSyntaxException pse) {
            callbacks.printError(pse.getMessage());
        }
        return false;
    }

    public Pattern getTokenExtractionPattern() {
        return tokenExtractionPattern;
    }

    public void setTokenExtractionPattern(Pattern pattern) {
        this.tokenExtractionPattern = pattern;
    }

    public boolean setTokenExtractionPattern(String patternString) {
        try {
            Pattern pattern = Pattern.compile(patternString);
            setTokenExtractionPattern(pattern);
            return true;
        } catch (PatternSyntaxException pse) {
            callbacks.printError(pse.getMessage());
        }
        return false;
    }

    public String getFormUrl() {
        return formUrlString;
    }

    public boolean setFormUrl(String formUrlString) {
        try {
	    formUrl = new URL(formUrlString);
            return true;
	} catch (MalformedURLException ex) {
            callbacks.printError(ex.getMessage());
	}
        return false;
    }

    @Override
    public void extensionUnloaded() {
        callbacks.printOutput("extensionUnloaded");
        guiPanel.saveSettings();
    }

}
