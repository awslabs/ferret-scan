# Detection types

Every type `ferret-scan` can report, with the description it puts in a SARIF rule.

**This file is generated.** It is rendered from `core.KnownTypes()` and
`sarif.GetRuleDescription` — the same sources the SARIF rule builder reads — so the
page and the report cannot disagree about a type. Regenerate with:

```
UPDATE_CHECK_DOCS=1 go test ./internal/formatters/sarif/ -run TestCheckPageIsUpToDate
```

Each SARIF finding's `helpUri` links to the anchor for its type, so a reviewer
reading a report in a code-scanning UI lands on the matching section here.

Types whose entry reads the generic description simply have no bespoke copy in the
registry yet; the detection itself is unaffected.

## Index

- [ABA_ROUTING](#aba_routing)
- [ALIBABA_ARN](#alibaba_arn)
- [AMERICAN_EXPRESS](#american_express)
- [API_KEY_OR_SECRET](#api_key_or_secret)
- [APPLE_CORPORATE](#apple_corporate)
- [APPLICATION_INFO](#application_info)
- [AUTHOR_INFO](#author_info)
- [AWS_ACCESS_KEY](#aws_access_key)
- [AWS_ARN](#aws_arn)
- [AWS_SECRET_ACCESS_KEY](#aws_secret_access_key)
- [AZURE_RESOURCE_ID](#azure_resource_id)
- [BUSINESS](#business)
- [COMPANY_INFO](#company_info)
- [CREDIT_CARD](#credit_card)
- [DATE_OF_BIRTH](#date_of_birth)
- [DEA_NUMBER](#dea_number)
- [DINERS_CLUB](#diners_club)
- [DISCOVER](#discover)
- [DISPOSABLE](#disposable)
- [DOCKER_TOKEN](#docker_token)
- [DOCUMENT_COMMENTS](#document_comments)
- [DRIVERS_LICENSE](#drivers_license)
- [EDUCATIONAL](#educational)
- [EMAIL](#email)
- [GCP_RESOURCE_NAME](#gcp_resource_name)
- [GITHUB](#github)
- [GITHUB_TOKEN](#github_token)
- [GITLAB_TOKEN](#gitlab_token)
- [GMAIL](#gmail)
- [GOOGLE_CLOUD_API_KEY](#google_cloud_api_key)
- [GOVERNMENT](#government)
- [IBAN](#iban)
- [IBM_CRN](#ibm_crn)
- [IMAGE_METADATA](#image_metadata)
- [INSURANCE_MEMBER_ID](#insurance_member_id)
- [INTELLECTUAL_PROPERTY](#intellectual_property)
- [IP_ADDRESS](#ip_address)
- [JCB](#jcb)
- [JWT_TOKEN](#jwt_token)
- [LAST_MODIFIED_BY](#last_modified_by)
- [MASTERCARD](#mastercard)
- [MEDICARE_MBI](#medicare_mbi)
- [MRN](#mrn)
- [NPI](#npi)
- [OCI_OCID](#oci_ocid)
- [OTPAUTH_URI](#otpauth_uri)
- [OTP_SECRET](#otp_secret)
- [PASSPORT](#passport)
- [PERSON_NAME](#person_name)
- [PHONE](#phone)
- [PO_BOX](#po_box)
- [RECOVERY_CODES](#recovery_codes)
- [SLACK_TOKEN](#slack_token)
- [SSH_PRIVATE_KEY](#ssh_private_key)
- [SSN](#ssn)
- [STRIPE_API_KEY](#stripe_api_key)
- [SWIFT_BIC](#swift_bic)
- [TEMPLATE_INFO](#template_info)
- [US_BANK_ACCOUNT](#us_bank_account)
- [US_MILITARY_ADDRESS](#us_military_address)
- [US_RURAL_ROUTE](#us_rural_route)
- [US_STREET_ADDRESS](#us_street_address)
- [VIN](#vin)
- [VISA](#visa)

## ABA_ROUTING

**ABA_ROUTING Detected**

Sensitive data of type ABA_ROUTING was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## ALIBABA_ARN

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

## AMERICAN_EXPRESS

**AMERICAN_EXPRESS Detected**

Sensitive data of type AMERICAN_EXPRESS was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## API_KEY_OR_SECRET

**API_KEY_OR_SECRET Detected**

Sensitive data of type API_KEY_OR_SECRET was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## APPLE_CORPORATE

**APPLE_CORPORATE Detected**

Sensitive data of type APPLE_CORPORATE was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## APPLICATION_INFO

**APPLICATION_INFO Detected**

Sensitive data of type APPLICATION_INFO was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## AUTHOR_INFO

**AUTHOR_INFO Detected**

Sensitive data of type AUTHOR_INFO was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## AWS_ACCESS_KEY

**AWS_ACCESS_KEY Detected**

Sensitive data of type AWS_ACCESS_KEY was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## AWS_ARN

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

## AWS_SECRET_ACCESS_KEY

**AWS_SECRET_ACCESS_KEY Detected**

Sensitive data of type AWS_SECRET_ACCESS_KEY was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## AZURE_RESOURCE_ID

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

## BUSINESS

**BUSINESS Detected**

Sensitive data of type BUSINESS was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## COMPANY_INFO

**COMPANY_INFO Detected**

Sensitive data of type COMPANY_INFO was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## CREDIT_CARD

**Credit Card Number Detected**

A credit card number pattern was detected in the scanned content. Credit card numbers are sensitive financial information that must be protected under PCI DSS and other regulations.

*What to do:* Credit card numbers must be protected according to PCI DSS requirements. They should never be stored in source code, logs, or unencrypted databases. Remove this credit card number immediately and ensure any payment processing uses PCI-compliant systems. Consider using tokenization services provided by payment processors.

## DATE_OF_BIRTH

**DATE_OF_BIRTH Detected**

Sensitive data of type DATE_OF_BIRTH was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## DEA_NUMBER

**DEA_NUMBER Detected**

Sensitive data of type DEA_NUMBER was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## DINERS_CLUB

**DINERS_CLUB Detected**

Sensitive data of type DINERS_CLUB was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## DISCOVER

**DISCOVER Detected**

Sensitive data of type DISCOVER was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## DISPOSABLE

**DISPOSABLE Detected**

Sensitive data of type DISPOSABLE was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## DOCKER_TOKEN

**DOCKER_TOKEN Detected**

Sensitive data of type DOCKER_TOKEN was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## DOCUMENT_COMMENTS

**DOCUMENT_COMMENTS Detected**

Sensitive data of type DOCUMENT_COMMENTS was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## DRIVERS_LICENSE

**DRIVERS_LICENSE Detected**

Sensitive data of type DRIVERS_LICENSE was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## EDUCATIONAL

**EDUCATIONAL Detected**

Sensitive data of type EDUCATIONAL was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## EMAIL

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## GCP_RESOURCE_NAME

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

## GITHUB

**GITHUB Detected**

Sensitive data of type GITHUB was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## GITHUB_TOKEN

**GITHUB_TOKEN Detected**

Sensitive data of type GITHUB_TOKEN was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## GITLAB_TOKEN

**GITLAB_TOKEN Detected**

Sensitive data of type GITLAB_TOKEN was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## GMAIL

**GMAIL Detected**

Sensitive data of type GMAIL was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## GOOGLE_CLOUD_API_KEY

**GOOGLE_CLOUD_API_KEY Detected**

Sensitive data of type GOOGLE_CLOUD_API_KEY was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## GOVERNMENT

**GOVERNMENT Detected**

Sensitive data of type GOVERNMENT was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## IBAN

**IBAN Detected**

Sensitive data of type IBAN was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## IBM_CRN

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

## IMAGE_METADATA

**IMAGE_METADATA Detected**

Sensitive data of type IMAGE_METADATA was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## INSURANCE_MEMBER_ID

**INSURANCE_MEMBER_ID Detected**

Sensitive data of type INSURANCE_MEMBER_ID was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## INTELLECTUAL_PROPERTY

**Potential Intellectual Property Detected**

Content that may contain intellectual property markers (copyright notices, trademarks, patents) was detected. This could indicate third-party IP that requires proper attribution or licensing.

*What to do:* Ensure that any third-party intellectual property is properly licensed and attributed. Review your organization's policies on using external code and content. If this is your organization's IP, ensure proper copyright notices are in place. For third-party content, verify compliance with license terms.

## IP_ADDRESS

**IP Address Detected**

An IP address was detected in the scanned content. IP addresses can be considered personally identifiable information under GDPR and other privacy regulations.

*What to do:* IP addresses are considered personal data under GDPR and similar regulations. Evaluate whether this IP address should be hardcoded. Consider using configuration files, environment variables, or service discovery mechanisms instead. If this is for testing, clearly document it as test data.

## JCB

**JCB Detected**

Sensitive data of type JCB was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## JWT_TOKEN

**JWT_TOKEN Detected**

Sensitive data of type JWT_TOKEN was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## LAST_MODIFIED_BY

**LAST_MODIFIED_BY Detected**

Sensitive data of type LAST_MODIFIED_BY was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## MASTERCARD

**MASTERCARD Detected**

Sensitive data of type MASTERCARD was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## MEDICARE_MBI

**MEDICARE_MBI Detected**

Sensitive data of type MEDICARE_MBI was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## MRN

**MRN Detected**

Sensitive data of type MRN was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## NPI

**NPI Detected**

Sensitive data of type NPI was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## OCI_OCID

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

## OTPAUTH_URI

**OTPAUTH_URI Detected**

Sensitive data of type OTPAUTH_URI was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## OTP_SECRET

**OTP_SECRET Detected**

Sensitive data of type OTP_SECRET was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## PASSPORT

**Passport Number Detected**

A passport number pattern was detected in the scanned content. Passport numbers are highly sensitive personally identifiable information that must be protected.

*What to do:* Passport numbers are protected under various privacy and identity theft prevention regulations. They should never be stored in source code or logs. Remove this passport number immediately and ensure it is stored in a secure, encrypted system with strict access controls and audit logging.

## PERSON_NAME

**Person Name Detected**

A person's name was detected in the scanned content. Names are considered personally identifiable information (PII) under various privacy regulations.

*What to do:* Person names are considered PII under GDPR, CCPA, and other privacy regulations. Evaluate whether this name should be present in the code. If it's test data, use clearly fictional names or anonymized identifiers. For production use, ensure names are stored securely with appropriate access controls and data retention policies.

## PHONE

**Phone Number Detected**

A phone number was detected in the scanned content. Phone numbers can be considered personally identifiable information (PII) depending on context and jurisdiction.

*What to do:* Phone numbers may be considered PII under various privacy regulations. Evaluate whether this phone number should be present in the code. If it's for testing purposes, use clearly fake numbers (e.g., 555-0100 to 555-0199 in North America). For production use, store phone numbers in secure configuration systems with appropriate access controls.

## PO_BOX

**PO_BOX Detected**

Sensitive data of type PO_BOX was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## RECOVERY_CODES

**RECOVERY_CODES Detected**

Sensitive data of type RECOVERY_CODES was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## SLACK_TOKEN

**SLACK_TOKEN Detected**

Sensitive data of type SLACK_TOKEN was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## SSH_PRIVATE_KEY

**SSH_PRIVATE_KEY Detected**

Sensitive data of type SSH_PRIVATE_KEY was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## SSN

**Social Security Number Detected**

A Social Security Number (SSN) pattern was detected in the scanned content. SSNs are highly sensitive personally identifiable information (PII) that must be protected under various regulations.

*What to do:* Social Security Numbers are protected under numerous regulations including GDPR, HIPAA, and various state privacy laws. SSNs should never be stored in source code, configuration files, or logs. Remove this SSN immediately and ensure it is stored in a secure, encrypted system with appropriate access controls. Consider implementing tokenization or other data protection mechanisms.

## STRIPE_API_KEY

**STRIPE_API_KEY Detected**

Sensitive data of type STRIPE_API_KEY was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## SWIFT_BIC

**SWIFT_BIC Detected**

Sensitive data of type SWIFT_BIC was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## TEMPLATE_INFO

**TEMPLATE_INFO Detected**

Sensitive data of type TEMPLATE_INFO was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## US_BANK_ACCOUNT

**US_BANK_ACCOUNT Detected**

Sensitive data of type US_BANK_ACCOUNT was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## US_MILITARY_ADDRESS

**US_MILITARY_ADDRESS Detected**

Sensitive data of type US_MILITARY_ADDRESS was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## US_RURAL_ROUTE

**US_RURAL_ROUTE Detected**

Sensitive data of type US_RURAL_ROUTE was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## US_STREET_ADDRESS

**US_STREET_ADDRESS Detected**

Sensitive data of type US_STREET_ADDRESS was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

## VIN

**Vehicle Identification Number Detected**

A Vehicle Identification Number (VIN) was detected in the scanned content. VINs can be used to identify vehicle owners and access personal information such as registration, insurance, and accident history.

*What to do:* VINs are linked to vehicle owner identity and can reveal personal information through public databases. They should not be stored in source code or logs. Remove VINs and use anonymized identifiers for testing. For production systems, store VINs in encrypted databases with appropriate access controls.

## VISA

**VISA Detected**

Sensitive data of type VISA was detected in the scanned content.

*What to do:* Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.

