# mailspring-auth-results
NOTE: This plugin works if the mail server support Authentication-Result header!

**mailspring-auth-results** is a security-focused plugin for Mailspring that analyzes email authentication headers and displays a clear summary of their status directly in the message view.

The plugin parses common authentication results and routing headers to help users quickly understand where a message came from and whether it passed standard email security checks.

## Features

The plugin automatically analyzes the following authentication mechanisms:

* **DKIM**
* **SPF**
* **DMARC**
* **ARC**

It also inspects the `Received` headers to extract useful routing information, including:

* **Origin server** (where the email was initially sent from)
* **Relay server** (the server that delivered the message to your mail server)
* **Source IP address**

## Security Indicators

In addition to authentication results, the plugin highlights several potentially suspicious situations:

* **Internal domain spoofing**
* **Reply-To domain mismatch**
* **Return-Path mismatch**
* **Suspicious top-level domains**
* Messages claiming to be from your organization but sent from external infrastructure

These indicators help identify phishing attempts and misconfigured email systems.

## Infrastructure Detection

The plugin attempts to identify common email delivery platforms by inspecting the mail relay chain, including:

* Google Workspace
* Microsoft 365
* Amazon SES
* SendGrid
* Mailgun

When detected, the delivery platform is displayed in the message metadata.

## Why This Plugin?

Email headers contain a lot of security information, but most email clients do not present it in an easy-to-read format.
This plugin extracts the most relevant signals and presents them directly in the message view, helping users quickly evaluate the authenticity of incoming emails.

## Installation

1. Download or clone this repository.
2. Install the plugin in Mailspring:

```
mailspring --install-plugin mailspring-auth-results
```

3. Restart Mailspring.

## License

MIT License


```THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.```



MI
