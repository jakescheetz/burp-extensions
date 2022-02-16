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
+========================================================================================+
*/


package burp;

public class HttpListener implements IHttpListener{



    private IExtensionHelpers helpers;

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        
        //build a byte array to process the information from the HTTP request
        byte[] request = messageInfo.getRequest();
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        requestInfo.getUrl();

        // logic to only process responses, not requests
        if (!messageIsRequest){

        }





        
    }
    
}
