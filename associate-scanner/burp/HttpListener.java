/*
+========================================================================================+
Author: Jake Scheetz

Date: Feb 2022

Title: Associate Scanner Extension for NetSPI-U Jan 2022

Description: Basic implementation of a passive scanner that analyzes the entirety of HTTP
             requests for a flag and then when a match is detected, it alerts the user by
             raising an issue with the severity (arbitrary), confidence (arbitrary), and
             the URL that the issue was raised from.

Project Structure: 
        BurpExtender.java -> 'main' file that calls from all the defintion files and
                              basically runs the over-arching logic for the program
        ~~~~~~~~~~~~~~~~~~~~
        HttpListener.java -> defines the logic for the passive http response analysis
                             and conversion of http data from bytes to strings
        ~~~~~~~~~~~~~~~~~~~~
        ScannerIssue.java -> defines what information that is alerted to the user of the 
                             extension and how the information is presented
+========================================================================================+
*/


package burp;

import java.net.URL;
import java.net.http.HttpResponse.ResponseInfo;

public class HttpListener implements IHttpListener{


    //instantiate the two classes needed for data manipulation and methods
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    //constructor for HTTPListener class
    public HttpListener(IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // logic check to only process responses, not requests
        if (!messageIsRequest){
            IRequestInfo requestInfo = this.helpers.analyzeRequest(messageInfo.getRequest());
            URL url = requestInfo.getUrl();

            //logic to check if URL is OOS (out of scope)
            if(!callbacks.isInScope(url)){
                callbacks.printOutput("The following URL was not in scope: " + url);
            }

            //grab request information
            byte[] response = messageInfo.getResponse();
            IResponseInfo responseInfo = this.helpers.analyzeResponse(response);

            //identify if the flag is in the response by changing the bytes to a string
            if (this.helpers.bytesToString(response).contains("123flag123")){
                this.callbacks.addScanIssue(new ScannerIssue(url, new IHttpRequestResponse[] {messageInfo}));
            }
        }   
    }
    
}

