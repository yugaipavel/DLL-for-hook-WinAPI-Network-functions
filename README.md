# DLL-for-hook-WinAPI-Network-functions

Network communication dll is an executable dll that monitors the received and transmitted network data of programs and scans them for the presence of malicious signatures. It intercepts functions from the libraries: winhttp.dll, wininet.dll, ws32_2.dll. Analyzes information about network connections created by the analyzed program and compares it with a list of known indicators of compromise (IoC). Analyzes the source code of web pages, including Javascript and links to other resources, for potential threats. To detect signatures, regular expressions were written for each, which are in the LevelDB database. This dll is a pipe client that sends messages to a pipe server named \\. \ Pipe \ WINAPINetworkDLL.

The following 5 vulnerabilities in HTML and Javascript code were selected:

• Microsoft Internet Explorer 11 - VBScript Execution Policy Bypass in MSHTML;

• Ubiquiti Networks UniFi 3.2.10 - Cross-Site Request Forgery;

• Balero CMS 0.7.2 - Multiple JS / HTML Injection Vulnerabilities;

• NPMJS gitlabhook 0.0.17 - 'repository' Remote Command Execution;

• Microsoft Excel 2007 - JavaScript Code Remote Denial of Service.
