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

import associateScanner.HttpListener;

public class BurpExtender implements IBurpExtender {
    final String extensionName = "Associate Scanner ::: Basic";
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
       //set the extension name
        callbacks.setExtensionName(extensionName);
        callbacks.registerHttpListener(new HttpListener(callbacks));
    }
    
}
