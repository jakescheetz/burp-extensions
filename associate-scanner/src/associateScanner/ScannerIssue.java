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

package associateScanner;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import java.net.URL;

public class ScannerIssue implements IScanIssue {

    //instantiate needed objects
    private URL url;
    private IHttpRequestResponse[] messages;

    //custom constructor for scanner issue class
    public ScannerIssue(URL url, IHttpRequestResponse[] messages){
        this.url = url;
        this.messages = messages;
    }

    @Override
    public URL getUrl() {
        // TODO Auto-generated method stub
        return this.url;
    }

    @Override
    public String getIssueName() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int getIssueType() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public String getSeverity() {
        // TODO Auto-generated method stub
        return "High";
    }

    @Override
    public String getConfidence() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getIssueBackground() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getRemediationBackground() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getIssueDetail() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getRemediationDetail() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        // TODO Auto-generated method stub
        return this.messages;
    }

    @Override
    public IHttpService getHttpService() {
        // TODO Auto-generated method stub
        return null;
    }
}
