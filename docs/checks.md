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
- [AOL](#aol)
- [API_KEY_OR_SECRET](#api_key_or_secret)
- [APPLE_CORPORATE](#apple_corporate)
- [APPLICATION_INFO](#application_info)
- [ATLASSIAN](#atlassian)
- [AUDIO_ARTIST_IDENTITY](#audio_artist_identity)
- [AUDIO_CONTACT_INFO](#audio_contact_info)
- [AUDIO_LOCATION_INFO](#audio_location_info)
- [AUDIO_METADATA](#audio_metadata)
- [AUTHOR_INFO](#author_info)
- [AWS_ACCESS_KEY](#aws_access_key)
- [AWS_ARN](#aws_arn)
- [AWS_SECRET_ACCESS_KEY](#aws_secret_access_key)
- [AZURE_RESOURCE_ID](#azure_resource_id)
- [BUSINESS](#business)
- [CERTIFICATE](#certificate)
- [CLOUD_RESOURCE_ID](#cloud_resource_id)
- [COMPANY_INFO](#company_info)
- [CREDIT_CARD](#credit_card)
- [CUSTOM_PROPERTY](#custom_property)
- [DATE_OF_BIRTH](#date_of_birth)
- [DEA_NUMBER](#dea_number)
- [DEVICE_INFO](#device_info)
- [DINERS_CLUB](#diners_club)
- [DISCOVER](#discover)
- [DISPOSABLE](#disposable)
- [DOCKER_TOKEN](#docker_token)
- [DOCUMENT_COMMENTS](#document_comments)
- [DOCUMENT_DESCRIPTION](#document_description)
- [DOCUMENT_KEYWORDS](#document_keywords)
- [DOCUMENT_METADATA](#document_metadata)
- [DRIVERS_LICENSE](#drivers_license)
- [EDUCATIONAL](#educational)
- [EMAIL](#email)
- [FASTMAIL](#fastmail)
- [GCP_RESOURCE_NAME](#gcp_resource_name)
- [GITHUB](#github)
- [GITHUB_TOKEN](#github_token)
- [GITLAB](#gitlab)
- [GITLAB_TOKEN](#gitlab_token)
- [GMAIL](#gmail)
- [GOOGLE_CLOUD_API_KEY](#google_cloud_api_key)
- [GOOGLE_WORKSPACE](#google_workspace)
- [GOVERNMENT](#government)
- [GPS](#gps)
- [IBAN](#iban)
- [IBM_CRN](#ibm_crn)
- [ICLOUD](#icloud)
- [IMAGE_METADATA](#image_metadata)
- [INSURANCE_MEMBER_ID](#insurance_member_id)
- [INTELLECTUAL_PROPERTY](#intellectual_property)
- [IP_ADDRESS](#ip_address)
- [JCB](#jcb)
- [JWT_TOKEN](#jwt_token)
- [LAST_MODIFIED_BY](#last_modified_by)
- [MAESTRO](#maestro)
- [MAIL_RU](#mail_ru)
- [MANAGER_INFO](#manager_info)
- [MASTERCARD](#mastercard)
- [MEDICARE_MBI](#medicare_mbi)
- [METADATA](#metadata)
- [MICROSOFT_365](#microsoft_365)
- [MRN](#mrn)
- [NPI](#npi)
- [OCI_OCID](#oci_ocid)
- [OTPAUTH_URI](#otpauth_uri)
- [OTP_SECRET](#otp_secret)
- [OUTLOOK](#outlook)
- [PASSPORT](#passport)
- [PERSON_NAME](#person_name)
- [PGP_PRIVATE_KEY](#pgp_private_key)
- [PHONE](#phone)
- [PO_BOX](#po_box)
- [PROTONMAIL](#protonmail)
- [RECOVERY_CODES](#recovery_codes)
- [SALESFORCE](#salesforce)
- [SLACK](#slack)
- [SLACK_TOKEN](#slack_token)
- [SOCIAL_MEDIA_CLUSTER](#social_media_cluster)
- [SOFTWARE_USER_PATH](#software_user_path)
- [SSH_PRIVATE_KEY](#ssh_private_key)
- [SSN](#ssn)
- [STRIPE_API_KEY](#stripe_api_key)
- [SWIFT_BIC](#swift_bic)
- [TEMPLATE_INFO](#template_info)
- [TUTANOTA](#tutanota)
- [UNIONPAY](#unionpay)
- [US_BANK_ACCOUNT](#us_bank_account)
- [US_MILITARY_ADDRESS](#us_military_address)
- [US_RURAL_ROUTE](#us_rural_route)
- [US_STREET_ADDRESS](#us_street_address)
- [VIDEO_CREATOR_INFO](#video_creator_info)
- [VIDEO_DEVICE_INFO](#video_device_info)
- [VIDEO_METADATA](#video_metadata)
- [VIN](#vin)
- [VISA](#visa)
- [YAHOO](#yahoo)
- [YANDEX](#yandex)
- [ZOHO](#zoho)

## ABA_ROUTING

**Bank Account Identifier Detected**

A bank account identifier — a US account number, an ABA routing number, an IBAN or a SWIFT/BIC code — was detected in the scanned content. A routing number together with an account number is sufficient to originate a debit against that account.

*What to do:* Remove the account identifier, or replace it with a documented test value. Note that routing and account numbers are damaging in COMBINATION: a routing number alone identifies only the institution, so check whether an account number appears nearby before deciding a finding is low risk. Where account details must be stored, hold them in a payments vault rather than in source, logs or shared documents.

## ALIBABA_ARN

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

## AMERICAN_EXPRESS

**Credit Card Number Detected**

A credit card number pattern was detected in the scanned content. Credit card numbers are sensitive financial information that must be protected under PCI DSS and other regulations.

*What to do:* Credit card numbers must be protected according to PCI DSS requirements. They should never be stored in source code, logs, or unencrypted databases. Remove this credit card number immediately and ensure any payment processing uses PCI-compliant systems. Consider using tokenization services provided by payment processors.

## AOL

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## API_KEY_OR_SECRET

**Secret or API Key Detected**

A potential secret, API key, password, or authentication token was detected in the scanned content. Exposed secrets can lead to unauthorized access and security breaches.

*What to do:* Secrets, API keys, and passwords should never be stored in source code or version control. Remove this secret immediately and rotate it if it has been committed. Use secret management systems like AWS Secrets Manager, HashiCorp Vault, or environment variables for storing sensitive credentials. Implement pre-commit hooks to prevent future secret commits.

## APPLE_CORPORATE

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## APPLICATION_INFO

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## ATLASSIAN

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## AUDIO_ARTIST_IDENTITY

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## AUDIO_CONTACT_INFO

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## AUDIO_LOCATION_INFO

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## AUDIO_METADATA

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## AUTHOR_INFO

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## AWS_ACCESS_KEY

**Secret or API Key Detected**

A potential secret, API key, password, or authentication token was detected in the scanned content. Exposed secrets can lead to unauthorized access and security breaches.

*What to do:* Secrets, API keys, and passwords should never be stored in source code or version control. Remove this secret immediately and rotate it if it has been committed. Use secret management systems like AWS Secrets Manager, HashiCorp Vault, or environment variables for storing sensitive credentials. Implement pre-commit hooks to prevent future secret commits.

## AWS_ARN

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

## AWS_SECRET_ACCESS_KEY

**Secret or API Key Detected**

A potential secret, API key, password, or authentication token was detected in the scanned content. Exposed secrets can lead to unauthorized access and security breaches.

*What to do:* Secrets, API keys, and passwords should never be stored in source code or version control. Remove this secret immediately and rotate it if it has been committed. Use secret management systems like AWS Secrets Manager, HashiCorp Vault, or environment variables for storing sensitive credentials. Implement pre-commit hooks to prevent future secret commits.

## AZURE_RESOURCE_ID

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

## BUSINESS

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## CERTIFICATE

**Secret or API Key Detected**

A potential secret, API key, password, or authentication token was detected in the scanned content. Exposed secrets can lead to unauthorized access and security breaches.

*What to do:* Secrets, API keys, and passwords should never be stored in source code or version control. Remove this secret immediately and rotate it if it has been committed. Use secret management systems like AWS Secrets Manager, HashiCorp Vault, or environment variables for storing sensitive credentials. Implement pre-commit hooks to prevent future secret commits.

## CLOUD_RESOURCE_ID

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

## COMPANY_INFO

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## CREDIT_CARD

**Credit Card Number Detected**

A credit card number pattern was detected in the scanned content. Credit card numbers are sensitive financial information that must be protected under PCI DSS and other regulations.

*What to do:* Credit card numbers must be protected according to PCI DSS requirements. They should never be stored in source code, logs, or unencrypted databases. Remove this credit card number immediately and ensure any payment processing uses PCI-compliant systems. Consider using tokenization services provided by payment processors.

## CUSTOM_PROPERTY

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## DATE_OF_BIRTH

**Date of Birth Detected**

A date of birth was detected in the scanned content. A date of birth is a common identity-verification factor and, combined with a name, is frequently enough to pass a knowledge-based authentication check.

*What to do:* Remove the date of birth or replace it with a synthetic one. Judge severity by what sits beside it: a date alone is weak, while a date next to a name or an account number is a usable identity-verification pair. Note that a date of birth has a very small search space, so hashing or truncating one does not make it private.

## DEA_NUMBER

**Medical Identifier Detected**

A healthcare identifier — a medical record number, a Medicare Beneficiary Identifier, an NPI, a DEA registration number or an insurance member ID — was detected in the scanned content. Most of these identify a PATIENT and are protected health information; an NPI identifies a PRACTITIONER and is published in a public registry, so it is the least sensitive of the group.

*What to do:* Treat a patient identifier as protected health information: remove it, or replace it with a synthetic value, and check whether the surrounding record must be handled under HIPAA or an equivalent regime. A DEA number additionally authorises controlled-substance prescribing, so it is a credential as well as an identifier. An NPI on its own is public information and usually needs no action — but an NPI beside a patient identifier links a named clinician to a named patient.

## DEVICE_INFO

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## DINERS_CLUB

**Credit Card Number Detected**

A credit card number pattern was detected in the scanned content. Credit card numbers are sensitive financial information that must be protected under PCI DSS and other regulations.

*What to do:* Credit card numbers must be protected according to PCI DSS requirements. They should never be stored in source code, logs, or unencrypted databases. Remove this credit card number immediately and ensure any payment processing uses PCI-compliant systems. Consider using tokenization services provided by payment processors.

## DISCOVER

**Credit Card Number Detected**

A credit card number pattern was detected in the scanned content. Credit card numbers are sensitive financial information that must be protected under PCI DSS and other regulations.

*What to do:* Credit card numbers must be protected according to PCI DSS requirements. They should never be stored in source code, logs, or unencrypted databases. Remove this credit card number immediately and ensure any payment processing uses PCI-compliant systems. Consider using tokenization services provided by payment processors.

## DISPOSABLE

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## DOCKER_TOKEN

**Secret or API Key Detected**

A potential secret, API key, password, or authentication token was detected in the scanned content. Exposed secrets can lead to unauthorized access and security breaches.

*What to do:* Secrets, API keys, and passwords should never be stored in source code or version control. Remove this secret immediately and rotate it if it has been committed. Use secret management systems like AWS Secrets Manager, HashiCorp Vault, or environment variables for storing sensitive credentials. Implement pre-commit hooks to prevent future secret commits.

## DOCUMENT_COMMENTS

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## DOCUMENT_DESCRIPTION

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## DOCUMENT_KEYWORDS

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## DOCUMENT_METADATA

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## DRIVERS_LICENSE

**Driver's License Number Detected**

A driver's license number was detected in the scanned content. A license number is a government-issued identity document number, and in many jurisdictions its format encodes personal details such as a date of birth or a name fragment.

*What to do:* Remove the license number or replace it with a synthetic value. Because several jurisdictions derive the number from the holder's name and date of birth, the number itself can disclose those details even without them appearing in the text. Formats vary by jurisdiction, so verify a finding against the issuing state's pattern before dismissing it.

## EDUCATIONAL

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## EMAIL

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## FASTMAIL

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## GCP_RESOURCE_NAME

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

## GITHUB

**Social Media Handle Detected**

A social media handle or username was detected in the scanned content. Social media identifiers can be used to link to personal profiles and may be considered PII in some contexts.

*What to do:* Social media handles can be used to identify individuals and may be considered personal information. Evaluate whether these handles should be present in the code. If they're for testing, use clearly fake handles. For production use, consider whether this information should be stored in a configuration system with appropriate access controls.

## GITHUB_TOKEN

**Secret or API Key Detected**

A potential secret, API key, password, or authentication token was detected in the scanned content. Exposed secrets can lead to unauthorized access and security breaches.

*What to do:* Secrets, API keys, and passwords should never be stored in source code or version control. Remove this secret immediately and rotate it if it has been committed. Use secret management systems like AWS Secrets Manager, HashiCorp Vault, or environment variables for storing sensitive credentials. Implement pre-commit hooks to prevent future secret commits.

## GITLAB

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## GITLAB_TOKEN

**Secret or API Key Detected**

A potential secret, API key, password, or authentication token was detected in the scanned content. Exposed secrets can lead to unauthorized access and security breaches.

*What to do:* Secrets, API keys, and passwords should never be stored in source code or version control. Remove this secret immediately and rotate it if it has been committed. Use secret management systems like AWS Secrets Manager, HashiCorp Vault, or environment variables for storing sensitive credentials. Implement pre-commit hooks to prevent future secret commits.

## GMAIL

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## GOOGLE_CLOUD_API_KEY

**Secret or API Key Detected**

A potential secret, API key, password, or authentication token was detected in the scanned content. Exposed secrets can lead to unauthorized access and security breaches.

*What to do:* Secrets, API keys, and passwords should never be stored in source code or version control. Remove this secret immediately and rotate it if it has been committed. Use secret management systems like AWS Secrets Manager, HashiCorp Vault, or environment variables for storing sensitive credentials. Implement pre-commit hooks to prevent future secret commits.

## GOOGLE_WORKSPACE

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## GOVERNMENT

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## GPS

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## IBAN

**Bank Account Identifier Detected**

A bank account identifier — a US account number, an ABA routing number, an IBAN or a SWIFT/BIC code — was detected in the scanned content. A routing number together with an account number is sufficient to originate a debit against that account.

*What to do:* Remove the account identifier, or replace it with a documented test value. Note that routing and account numbers are damaging in COMBINATION: a routing number alone identifies only the institution, so check whether an account number appears nearby before deciding a finding is low risk. Where account details must be stored, hold them in a payments vault rather than in source, logs or shared documents.

## IBM_CRN

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

## ICLOUD

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## IMAGE_METADATA

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## INSURANCE_MEMBER_ID

**Medical Identifier Detected**

A healthcare identifier — a medical record number, a Medicare Beneficiary Identifier, an NPI, a DEA registration number or an insurance member ID — was detected in the scanned content. Most of these identify a PATIENT and are protected health information; an NPI identifies a PRACTITIONER and is published in a public registry, so it is the least sensitive of the group.

*What to do:* Treat a patient identifier as protected health information: remove it, or replace it with a synthetic value, and check whether the surrounding record must be handled under HIPAA or an equivalent regime. A DEA number additionally authorises controlled-substance prescribing, so it is a credential as well as an identifier. An NPI on its own is public information and usually needs no action — but an NPI beside a patient identifier links a named clinician to a named patient.

## INTELLECTUAL_PROPERTY

**Potential Intellectual Property Detected**

Content that may contain intellectual property markers (copyright notices, trademarks, patents) was detected. This could indicate third-party IP that requires proper attribution or licensing.

*What to do:* Ensure that any third-party intellectual property is properly licensed and attributed. Review your organization's policies on using external code and content. If this is your organization's IP, ensure proper copyright notices are in place. For third-party content, verify compliance with license terms.

## IP_ADDRESS

**IP Address Detected**

An IP address was detected in the scanned content. IP addresses can be considered personally identifiable information under GDPR and other privacy regulations.

*What to do:* IP addresses are considered personal data under GDPR and similar regulations. Evaluate whether this IP address should be hardcoded. Consider using configuration files, environment variables, or service discovery mechanisms instead. If this is for testing, clearly document it as test data.

## JCB

**Credit Card Number Detected**

A credit card number pattern was detected in the scanned content. Credit card numbers are sensitive financial information that must be protected under PCI DSS and other regulations.

*What to do:* Credit card numbers must be protected according to PCI DSS requirements. They should never be stored in source code, logs, or unencrypted databases. Remove this credit card number immediately and ensure any payment processing uses PCI-compliant systems. Consider using tokenization services provided by payment processors.

## JWT_TOKEN

**Secret or API Key Detected**

A potential secret, API key, password, or authentication token was detected in the scanned content. Exposed secrets can lead to unauthorized access and security breaches.

*What to do:* Secrets, API keys, and passwords should never be stored in source code or version control. Remove this secret immediately and rotate it if it has been committed. Use secret management systems like AWS Secrets Manager, HashiCorp Vault, or environment variables for storing sensitive credentials. Implement pre-commit hooks to prevent future secret commits.

## LAST_MODIFIED_BY

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## MAESTRO

**Credit Card Number Detected**

A credit card number pattern was detected in the scanned content. Credit card numbers are sensitive financial information that must be protected under PCI DSS and other regulations.

*What to do:* Credit card numbers must be protected according to PCI DSS requirements. They should never be stored in source code, logs, or unencrypted databases. Remove this credit card number immediately and ensure any payment processing uses PCI-compliant systems. Consider using tokenization services provided by payment processors.

## MAIL_RU

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## MANAGER_INFO

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## MASTERCARD

**Credit Card Number Detected**

A credit card number pattern was detected in the scanned content. Credit card numbers are sensitive financial information that must be protected under PCI DSS and other regulations.

*What to do:* Credit card numbers must be protected according to PCI DSS requirements. They should never be stored in source code, logs, or unencrypted databases. Remove this credit card number immediately and ensure any payment processing uses PCI-compliant systems. Consider using tokenization services provided by payment processors.

## MEDICARE_MBI

**Medical Identifier Detected**

A healthcare identifier — a medical record number, a Medicare Beneficiary Identifier, an NPI, a DEA registration number or an insurance member ID — was detected in the scanned content. Most of these identify a PATIENT and are protected health information; an NPI identifies a PRACTITIONER and is published in a public registry, so it is the least sensitive of the group.

*What to do:* Treat a patient identifier as protected health information: remove it, or replace it with a synthetic value, and check whether the surrounding record must be handled under HIPAA or an equivalent regime. A DEA number additionally authorises controlled-substance prescribing, so it is a credential as well as an identifier. An NPI on its own is public information and usually needs no action — but an NPI beside a patient identifier links a named clinician to a named patient.

## METADATA

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## MICROSOFT_365

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## MRN

**Medical Identifier Detected**

A healthcare identifier — a medical record number, a Medicare Beneficiary Identifier, an NPI, a DEA registration number or an insurance member ID — was detected in the scanned content. Most of these identify a PATIENT and are protected health information; an NPI identifies a PRACTITIONER and is published in a public registry, so it is the least sensitive of the group.

*What to do:* Treat a patient identifier as protected health information: remove it, or replace it with a synthetic value, and check whether the surrounding record must be handled under HIPAA or an equivalent regime. A DEA number additionally authorises controlled-substance prescribing, so it is a credential as well as an identifier. An NPI on its own is public information and usually needs no action — but an NPI beside a patient identifier links a named clinician to a named patient.

## NPI

**Medical Identifier Detected**

A healthcare identifier — a medical record number, a Medicare Beneficiary Identifier, an NPI, a DEA registration number or an insurance member ID — was detected in the scanned content. Most of these identify a PATIENT and are protected health information; an NPI identifies a PRACTITIONER and is published in a public registry, so it is the least sensitive of the group.

*What to do:* Treat a patient identifier as protected health information: remove it, or replace it with a synthetic value, and check whether the surrounding record must be handled under HIPAA or an equivalent regime. A DEA number additionally authorises controlled-substance prescribing, so it is a credential as well as an identifier. An NPI on its own is public information and usually needs no action — but an NPI beside a patient identifier links a named clinician to a named patient.

## OCI_OCID

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

## OTPAUTH_URI

**Multi-Factor Authentication Secret Detected**

A multi-factor authentication secret — a TOTP/HOTP shared secret, an otpauth:// provisioning URI or a set of account recovery codes — was detected in the scanned content. These are not transient codes: the SEED generates every future code for the account, so disclosing it defeats the second factor permanently until the account is re-enrolled.

*What to do:* Treat this as a credential disclosure, not a configuration mistake. Re-enrol the account's second factor and regenerate its recovery codes; removing the value from the file does not undo the exposure, because whoever saw the seed can still generate codes. Provisioning URIs are commonly pasted from a QR-code export, so check for others nearby.

## OTP_SECRET

**Multi-Factor Authentication Secret Detected**

A multi-factor authentication secret — a TOTP/HOTP shared secret, an otpauth:// provisioning URI or a set of account recovery codes — was detected in the scanned content. These are not transient codes: the SEED generates every future code for the account, so disclosing it defeats the second factor permanently until the account is re-enrolled.

*What to do:* Treat this as a credential disclosure, not a configuration mistake. Re-enrol the account's second factor and regenerate its recovery codes; removing the value from the file does not undo the exposure, because whoever saw the seed can still generate codes. Provisioning URIs are commonly pasted from a QR-code export, so check for others nearby.

## OUTLOOK

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## PASSPORT

**Passport Number Detected**

A passport number pattern was detected in the scanned content. Passport numbers are highly sensitive personally identifiable information that must be protected.

*What to do:* Passport numbers are protected under various privacy and identity theft prevention regulations. They should never be stored in source code or logs. Remove this passport number immediately and ensure it is stored in a secure, encrypted system with strict access controls and audit logging.

## PERSON_NAME

**Person Name Detected**

A person's name was detected in the scanned content. Names are considered personally identifiable information (PII) under various privacy regulations.

*What to do:* Person names are considered PII under GDPR, CCPA, and other privacy regulations. Evaluate whether this name should be present in the code. If it's test data, use clearly fictional names or anonymized identifiers. For production use, ensure names are stored securely with appropriate access controls and data retention policies.

## PGP_PRIVATE_KEY

**Secret or API Key Detected**

A potential secret, API key, password, or authentication token was detected in the scanned content. Exposed secrets can lead to unauthorized access and security breaches.

*What to do:* Secrets, API keys, and passwords should never be stored in source code or version control. Remove this secret immediately and rotate it if it has been committed. Use secret management systems like AWS Secrets Manager, HashiCorp Vault, or environment variables for storing sensitive credentials. Implement pre-commit hooks to prevent future secret commits.

## PHONE

**Phone Number Detected**

A phone number was detected in the scanned content. Phone numbers can be considered personally identifiable information (PII) depending on context and jurisdiction.

*What to do:* Phone numbers may be considered PII under various privacy regulations. Evaluate whether this phone number should be present in the code. If it's for testing purposes, use clearly fake numbers (e.g., 555-0100 to 555-0199 in North America). For production use, store phone numbers in secure configuration systems with appropriate access controls.

## PO_BOX

**Physical Address Detected**

A physical postal address — a street address, a PO box, a rural route or a US military (APO/FPO/DPO) address — was detected in the scanned content. An address locates a person, and a military address additionally reveals a unit assignment.

*What to do:* Remove the address or replace it with a documented example. An address is most sensitive in combination with a name or an account identifier, so check what sits beside it before judging severity. A military APO/FPO/DPO address should be treated as more sensitive than a commercial one because it can disclose a unit's location and posting.

## PROTONMAIL

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## RECOVERY_CODES

**Multi-Factor Authentication Secret Detected**

A multi-factor authentication secret — a TOTP/HOTP shared secret, an otpauth:// provisioning URI or a set of account recovery codes — was detected in the scanned content. These are not transient codes: the SEED generates every future code for the account, so disclosing it defeats the second factor permanently until the account is re-enrolled.

*What to do:* Treat this as a credential disclosure, not a configuration mistake. Re-enrol the account's second factor and regenerate its recovery codes; removing the value from the file does not undo the exposure, because whoever saw the seed can still generate codes. Provisioning URIs are commonly pasted from a QR-code export, so check for others nearby.

## SALESFORCE

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## SLACK

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## SLACK_TOKEN

**Secret or API Key Detected**

A potential secret, API key, password, or authentication token was detected in the scanned content. Exposed secrets can lead to unauthorized access and security breaches.

*What to do:* Secrets, API keys, and passwords should never be stored in source code or version control. Remove this secret immediately and rotate it if it has been committed. Use secret management systems like AWS Secrets Manager, HashiCorp Vault, or environment variables for storing sensitive credentials. Implement pre-commit hooks to prevent future secret commits.

## SOCIAL_MEDIA_CLUSTER

**Social Media Handle Detected**

A social media handle or username was detected in the scanned content. Social media identifiers can be used to link to personal profiles and may be considered PII in some contexts.

*What to do:* Social media handles can be used to identify individuals and may be considered personal information. Evaluate whether these handles should be present in the code. If they're for testing, use clearly fake handles. For production use, consider whether this information should be stored in a configuration system with appropriate access controls.

## SOFTWARE_USER_PATH

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## SSH_PRIVATE_KEY

**Secret or API Key Detected**

A potential secret, API key, password, or authentication token was detected in the scanned content. Exposed secrets can lead to unauthorized access and security breaches.

*What to do:* Secrets, API keys, and passwords should never be stored in source code or version control. Remove this secret immediately and rotate it if it has been committed. Use secret management systems like AWS Secrets Manager, HashiCorp Vault, or environment variables for storing sensitive credentials. Implement pre-commit hooks to prevent future secret commits.

## SSN

**Social Security Number Detected**

A Social Security Number (SSN) pattern was detected in the scanned content. SSNs are highly sensitive personally identifiable information (PII) that must be protected under various regulations.

*What to do:* Social Security Numbers are protected under numerous regulations including GDPR, HIPAA, and various state privacy laws. SSNs should never be stored in source code, configuration files, or logs. Remove this SSN immediately and ensure it is stored in a secure, encrypted system with appropriate access controls. Consider implementing tokenization or other data protection mechanisms.

## STRIPE_API_KEY

**Secret or API Key Detected**

A potential secret, API key, password, or authentication token was detected in the scanned content. Exposed secrets can lead to unauthorized access and security breaches.

*What to do:* Secrets, API keys, and passwords should never be stored in source code or version control. Remove this secret immediately and rotate it if it has been committed. Use secret management systems like AWS Secrets Manager, HashiCorp Vault, or environment variables for storing sensitive credentials. Implement pre-commit hooks to prevent future secret commits.

## SWIFT_BIC

**Bank Account Identifier Detected**

A bank account identifier — a US account number, an ABA routing number, an IBAN or a SWIFT/BIC code — was detected in the scanned content. A routing number together with an account number is sufficient to originate a debit against that account.

*What to do:* Remove the account identifier, or replace it with a documented test value. Note that routing and account numbers are damaging in COMBINATION: a routing number alone identifies only the institution, so check whether an account number appears nearby before deciding a finding is low risk. Where account details must be stored, hold them in a payments vault rather than in source, logs or shared documents.

## TEMPLATE_INFO

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## TUTANOTA

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## UNIONPAY

**Credit Card Number Detected**

A credit card number pattern was detected in the scanned content. Credit card numbers are sensitive financial information that must be protected under PCI DSS and other regulations.

*What to do:* Credit card numbers must be protected according to PCI DSS requirements. They should never be stored in source code, logs, or unencrypted databases. Remove this credit card number immediately and ensure any payment processing uses PCI-compliant systems. Consider using tokenization services provided by payment processors.

## US_BANK_ACCOUNT

**Bank Account Identifier Detected**

A bank account identifier — a US account number, an ABA routing number, an IBAN or a SWIFT/BIC code — was detected in the scanned content. A routing number together with an account number is sufficient to originate a debit against that account.

*What to do:* Remove the account identifier, or replace it with a documented test value. Note that routing and account numbers are damaging in COMBINATION: a routing number alone identifies only the institution, so check whether an account number appears nearby before deciding a finding is low risk. Where account details must be stored, hold them in a payments vault rather than in source, logs or shared documents.

## US_MILITARY_ADDRESS

**Physical Address Detected**

A physical postal address — a street address, a PO box, a rural route or a US military (APO/FPO/DPO) address — was detected in the scanned content. An address locates a person, and a military address additionally reveals a unit assignment.

*What to do:* Remove the address or replace it with a documented example. An address is most sensitive in combination with a name or an account identifier, so check what sits beside it before judging severity. A military APO/FPO/DPO address should be treated as more sensitive than a commercial one because it can disclose a unit's location and posting.

## US_RURAL_ROUTE

**Physical Address Detected**

A physical postal address — a street address, a PO box, a rural route or a US military (APO/FPO/DPO) address — was detected in the scanned content. An address locates a person, and a military address additionally reveals a unit assignment.

*What to do:* Remove the address or replace it with a documented example. An address is most sensitive in combination with a name or an account identifier, so check what sits beside it before judging severity. A military APO/FPO/DPO address should be treated as more sensitive than a commercial one because it can disclose a unit's location and posting.

## US_STREET_ADDRESS

**Physical Address Detected**

A physical postal address — a street address, a PO box, a rural route or a US military (APO/FPO/DPO) address — was detected in the scanned content. An address locates a person, and a military address additionally reveals a unit assignment.

*What to do:* Remove the address or replace it with a documented example. An address is most sensitive in combination with a name or an account identifier, so check what sits beside it before judging severity. A military APO/FPO/DPO address should be treated as more sensitive than a commercial one because it can disclose a unit's location and posting.

## VIDEO_CREATOR_INFO

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## VIDEO_DEVICE_INFO

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## VIDEO_METADATA

**Sensitive Metadata Detected**

Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.

*What to do:* File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.

## VIN

**Vehicle Identification Number Detected**

A Vehicle Identification Number (VIN) was detected in the scanned content. VINs can be used to identify vehicle owners and access personal information such as registration, insurance, and accident history.

*What to do:* VINs are linked to vehicle owner identity and can reveal personal information through public databases. They should not be stored in source code or logs. Remove VINs and use anonymized identifiers for testing. For production systems, store VINs in encrypted databases with appropriate access controls.

## VISA

**Credit Card Number Detected**

A credit card number pattern was detected in the scanned content. Credit card numbers are sensitive financial information that must be protected under PCI DSS and other regulations.

*What to do:* Credit card numbers must be protected according to PCI DSS requirements. They should never be stored in source code, logs, or unencrypted databases. Remove this credit card number immediately and ensure any payment processing uses PCI-compliant systems. Consider using tokenization services provided by payment processors.

## YAHOO

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## YANDEX

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

## ZOHO

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

