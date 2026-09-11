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

**ABA Routing Number Detected**

A nine-digit ABA routing number was detected. It falls in an assigned Federal Reserve prefix range and passes the ABA check-digit formula, so it identifies a real US financial institution. A routing number alone is not secret — banks publish theirs — but paired with an account number it is everything needed to originate an ACH debit.

*What to do:* Check whether an account number appears nearby: the PAIR is the disclosure, and this tool reports US_BANK_ACCOUNT separately. A routing number on its own in a payment integration is usually legitimate configuration, but it should still come from a secret store rather than a committed file, so a change of banking partner does not require a code change.

*Short form (gitlab-sast):* Move banking coordinates into configuration a deployment supplies. If an account number appears on the same record, treat the pair as a payment-credential exposure.

## ALIBABA_ARN

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

*Short form (gitlab-sast):* Remove the resource identifier and supply resource identifiers from deployment configuration. They name real infrastructure, which helps an attacker map an environment and target it directly.

## AMERICAN_EXPRESS

**American Express Card Number Detected**

A payment card number in the American Express range was detected. It passed the Luhn check digit and its issuer identification number (IIN) is one American Express issues, and it is 15 digits rather than 16. Primary account numbers are cardholder data under PCI DSS and must not be stored in source, logs or configuration.

*What to do:* If this is a real card number, treat it as a PCI DSS incident: remove it from the file AND from version-control history, then have the card reissued, because history rewriting does not recall a number an attacker may already have cloned. If it is test data, use the brand's published test numbers, which are Luhn-valid but declined by every processor.

*Short form (gitlab-sast):* Remove or mask credit card numbers. Consider using tokenization for legitimate payment processing needs.

## API_KEY_OR_SECRET

**API Key or Secret Detected**

A value in the shape of an API key or shared secret was detected, assigned to a name that indicates it is a credential. The specific service is not identified, so the scope of access cannot be inferred from the value alone.

*What to do:* Identify the service from the surrounding code before deciding urgency; a generic match can be anything from a public analytics key to an administrative token. If it grants access, revoke and reissue it, then load it from a secret manager or environment variable at runtime.

*Short form (gitlab-sast):* Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.

## APPLE_CORPORATE

**Apple Corporate Email Address Detected**

An email address on an Apple corporate domain was detected.

*What to do:* Treat as a business address: identifies a person and their employer, is a phishing target, and does not belong in committed fixtures. Use the reserved example.com domain instead.

*Short form (gitlab-sast):* Replace with an example.com address, as for any business email in a fixture.

## APPLICATION_INFO

**Authoring Application Metadata Detected**

Application metadata was detected in a document's properties, recording the software and often the exact version used to create the file.

*What to do:* Not personal data, but useful to an attacker: a precise application version narrows which known vulnerabilities apply to the sender's environment, and a fleet-wide version tells them what to target. Strip document properties on external publication.

*Short form (gitlab-sast):* Strip document properties. Precise version strings help an attacker select exploits for your environment.

## AUTHOR_INFO

**Document Author Metadata Detected**

Author metadata was detected in a document's properties. This field survives copying, emailing and conversion, and it records who created the file rather than anything visible in its contents.

*What to do:* The risk is that it is invisible: a document reviewed for content still carries the author's name, and in many organisations that is a username. Strip document properties before publishing externally — most office suites offer a document inspector for exactly this.

*Short form (gitlab-sast):* Strip document properties before external publication. Author metadata survives copying and is not visible in the document body.

## AWS_ACCESS_KEY

**AWS Access Key ID Detected**

An AWS access key ID was detected. The ID is not itself a secret, but it identifies a specific IAM principal and is half of a long-lived credential pair — so its presence indicates long-lived keys are in use, and the matching secret access key is often nearby or in the same history.

*What to do:* Search the file and the repository history for the matching secret access key; a key ID with its secret is a usable credential. Prefer eliminating the credential class rather than rotating it: IAM roles, instance profiles or IAM Roles Anywhere remove the long-lived pair entirely. If the pair was exposed, deactivate the key and review CloudTrail for use you did not authorise.

*Short form (gitlab-sast):* Remove AWS credentials immediately and rotate them. Use IAM roles or environment variables instead.

## AWS_ARN

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

*Short form (gitlab-sast):* Remove the ARN and supply resource identifiers from deployment configuration. They name real infrastructure, which helps an attacker map an environment and target it directly.

## AWS_SECRET_ACCESS_KEY

**AWS Secret Access Key Detected**

An AWS secret access key was detected. This is the secret half of a long-lived AWS credential pair and grants every permission attached to its IAM principal, for as long as the key stays active.

*What to do:* Treat this as an active compromise, not a hygiene issue. Deactivate and delete the key immediately, then review CloudTrail for unauthorised use — an exposed key is typically exercised within minutes of reaching a public repository. Replace it with a role rather than a new key pair.

*Short form (gitlab-sast):* Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.

## AZURE_RESOURCE_ID

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

*Short form (gitlab-sast):* Remove the resource ID and supply resource identifiers from deployment configuration. They name real infrastructure, which helps an attacker map an environment and target it directly.

## BUSINESS

**Business Email Address Detected**

An email address on a domain that is not a known consumer, disposable, educational or government provider was detected — so it is most likely a corporate or organisational address. A business address identifies both a person and their employer.

*What to do:* Business addresses are frequently published, which lowers the confidentiality concern, but they are the primary target for phishing and credential stuffing, so a harvested list has real value. Remove them from committed fixtures; use the reserved example.com domain instead.

*Short form (gitlab-sast):* Replace with an address on the reserved example.com domain. Business addresses are the main target for phishing lists.

## COMPANY_INFO

**Company Metadata Detected**

Company metadata was detected in a document's properties, recording the organisation configured in the authoring application.

*What to do:* Usually low sensitivity, since the company is often obvious from the document itself. It matters when a document is meant to be attributable to someone else — a white-labelled report, or a template reused by a partner — where the metadata contradicts the visible branding.

*Short form (gitlab-sast):* Low risk in general. Strip it when a document is meant to be attributed to another party.

## CREDIT_CARD

**Credit Card Number Detected**

A credit card number pattern was detected in the scanned content. Credit card numbers are sensitive financial information that must be protected under PCI DSS and other regulations.

*What to do:* Credit card numbers must be protected according to PCI DSS requirements. They should never be stored in source code, logs, or unencrypted databases. Remove this credit card number immediately and ensure any payment processing uses PCI-compliant systems. Consider using tokenization services provided by payment processors.

*Short form (gitlab-sast):* Remove or mask credit card numbers. Consider using tokenization for legitimate payment processing needs.

## DATE_OF_BIRTH

**Date of Birth Detected**

A date of birth was detected, labelled as such by nearby text rather than inferred from the digits — any date can look like a birth date, so the label is what makes this a finding. Date of birth is a quasi-identifier: weak alone, but combined with a name or postcode it identifies most people uniquely.

*What to do:* Judge this by what it sits beside. A birth date in a record with a name, address or member ID is a re-identification risk and often the field that makes a dataset personal data. If the data must be retained, consider storing only the year, or an age band, which usually serves the same purpose.

*Short form (gitlab-sast):* Remove or coarsen the date — a year or age band usually serves the purpose. Combined with a name it is enough to identify most individuals.

## DEA_NUMBER

**DEA Registration Number Detected**

A DEA registration number was detected and it passes the DEA check-digit rule. It identifies a practitioner authorised to prescribe controlled substances.

*What to do:* A DEA number is used to write prescriptions, so exposure enables prescription fraud in the practitioner's name — a different risk from ordinary PII, and one the practitioner will want to know about. Remove it and notify the registrant if it was exposed.

*Short form (gitlab-sast):* Remove the DEA number and notify the registrant if it was exposed — the practical risk is prescription fraud in their name.

## DINERS_CLUB

**Diners Club Card Number Detected**

A payment card number in the Diners Club range was detected. It passed the Luhn check digit and its issuer identification number (IIN) is one Diners Club issues, which is 14 digits. Primary account numbers are cardholder data under PCI DSS and must not be stored in source, logs or configuration.

*What to do:* If this is a real card number, treat it as a PCI DSS incident: remove it from the file AND from version-control history, then have the card reissued, because history rewriting does not recall a number an attacker may already have cloned. If it is test data, use the brand's published test numbers, which are Luhn-valid but declined by every processor.

*Short form (gitlab-sast):* Remove or mask credit card numbers. Consider using tokenization for legitimate payment processing needs.

## DISCOVER

**Discover Card Number Detected**

A payment card number in the Discover range was detected. It passed the Luhn check digit and its issuer identification number (IIN) is one Discover issues. Primary account numbers are cardholder data under PCI DSS and must not be stored in source, logs or configuration.

*What to do:* If this is a real card number, treat it as a PCI DSS incident: remove it from the file AND from version-control history, then have the card reissued, because history rewriting does not recall a number an attacker may already have cloned. If it is test data, use the brand's published test numbers, which are Luhn-valid but declined by every processor.

*Short form (gitlab-sast):* Remove or mask credit card numbers. Consider using tokenization for legitimate payment processing needs.

## DISPOSABLE

**Disposable Email Address Detected**

An email address on a known disposable or temporary-mail provider was detected. These mailboxes are created to receive a single message and are often publicly readable by anyone who knows the address.

*What to do:* Low privacy sensitivity — the mailbox is intended to be throwaway — but a strong signal for abuse detection: disposable addresses in a user table usually mean sign-up abuse, trial farming or bypassed verification. Worth reviewing as a fraud indicator rather than a data-protection one.

*Short form (gitlab-sast):* Low privacy risk, but review as an abuse signal — disposable addresses in a user table usually indicate sign-up abuse.

## DOCKER_TOKEN

**Docker Registry Token Detected**

A Docker registry credential was detected. It authenticates pushes and pulls for a registry namespace.

*What to do:* A push credential is a supply-chain risk: an attacker who can push a tag can have it deployed by anything that pulls that tag. Revoke it in the registry, then use a short-lived token issued by CI, and pin images by digest so a replaced tag cannot silently change what you run.

*Short form (gitlab-sast):* Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.

## DOCUMENT_COMMENTS

**Document Comments Detected**

Comments or tracked annotations were detected in a document. Comments are frequently invisible in the default view and are not removed by exporting or printing to PDF in every tool.

*What to do:* Comments are where the candid content lives: pricing rationale, negotiating positions, names of individuals, and text deleted from the visible document. Review them explicitly, then accept or remove all tracked changes and delete all comments before sending a document outside the organisation.

*Short form (gitlab-sast):* Review and delete comments and tracked changes before external distribution — they hold content that is not visible in the document body.

## DRIVERS_LICENSE

**Driver's License Number Detected**

A driver's license number was detected in a format one or more US states issue. State formats differ widely and most have no checksum, so a nearby state name or label is what raises confidence. A license number is a government identifier commonly accepted as proof of identity.

*What to do:* Treat as a government identifier: it is used for identity verification, so exposure supports identity theft rather than just profiling. Unlike a card it cannot be reissued quickly. Remove it, and prefer storing a verification RESULT rather than the number itself.

*Short form (gitlab-sast):* Remove the license number. Store the outcome of an identity check rather than the identifier, which cannot be reissued quickly.

## EDUCATIONAL

**Educational Email Address Detected**

An email address on an educational domain was detected. These identify a person and their institution, and frequently belong to students.

*What to do:* Student data attracts additional obligations in several jurisdictions — FERPA in the US, and age-related provisions elsewhere — so an educational address can raise the compliance bar above an ordinary business address. Confirm whether the dataset is subject to those rules.

*Short form (gitlab-sast):* Remove and check obligations: student data can attract FERPA or age-related requirements beyond ordinary personal data.

## EMAIL

**Email Address Detected**

An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.

*What to do:* Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.

*Short form (gitlab-sast):* Remove email addresses or replace with example addresses (e.g., user@domain.example).

## GCP_RESOURCE_NAME

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

*Short form (gitlab-sast):* Remove the resource name and supply resource identifiers from deployment configuration. They name real infrastructure, which helps an attacker map an environment and target it directly.

## GITHUB

**GitHub Email Address Detected**

An email address associated with GitHub — including the noreply forms GitHub issues for commit authorship — was detected.

*What to do:* A noreply address is designed to be public and needs no remediation; it exists so that commits do not expose a real mailbox. A non-noreply GitHub address should be treated as a business address. Check which form this is before acting.

*Short form (gitlab-sast):* A noreply form is intended to be public and needs no action. Treat any other GitHub address as a business email.

## GITHUB_TOKEN

**GitHub Token Detected**

A GitHub token was detected. Its prefix identifies it as a GitHub credential — personal access, OAuth, app installation or refresh — and the scopes attached to it determine what an attacker can read or push.

*What to do:* Assume the repositories and organisations that token can reach are compromised, including any CI secrets reachable from a workflow it can trigger. Revoke it in GitHub settings, then prefer a fine-grained token or a short-lived GITHUB_TOKEN supplied by Actions over a long-lived personal token. GitHub also scans public pushes and may have revoked it already.

*Short form (gitlab-sast):* Remove GitHub tokens and regenerate them. Use GitHub Actions secrets or environment variables instead.

## GITLAB_TOKEN

**GitLab Token Detected**

A GitLab token was detected. Depending on type it may grant repository, registry, or full API access to a project or group for the life of the token.

*What to do:* Assume every project the token can reach is compromised, including package registries and CI variables. Revoke it in GitLab, then use a project access token with the narrowest scope, or a CI job token that expires with the job.

*Short form (gitlab-sast):* Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.

## GMAIL

**Gmail Address Detected**

A Gmail address was detected. A consumer mailbox is personal data and, unlike a role address, it identifies an individual rather than a function.

*What to do:* Personal addresses carry more privacy weight than corporate ones: they usually persist for life and are reused across services, so they are effective join keys between datasets. Replace with example.com in fixtures and keep real addresses in a system with access control.

*Short form (gitlab-sast):* Replace with an example.com address. Personal mailboxes are long-lived and act as join keys across datasets.

## GOOGLE_CLOUD_API_KEY

**Google Cloud API Key Detected**

A Google Cloud API key was detected. API keys identify a project rather than a principal and are often unrestricted by default, so the same key may reach several enabled services.

*What to do:* Check the key's API and application restrictions in the console — an unrestricted key is usable by anyone who has the string. Regenerate it, then add both API restrictions and application restrictions, or replace it with a service account and Workload Identity where the calling service supports it.

*Short form (gitlab-sast):* Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.

## GOVERNMENT

**Government Email Address Detected**

An email address on a government domain was detected. It identifies a public-sector employee and their agency.

*What to do:* Usually published, so rarely confidential in itself — but a government address is a high-value phishing target and its presence may indicate the surrounding data relates to public-sector work with its own handling rules. Remove from fixtures and use example.com.

*Short form (gitlab-sast):* Replace with example.com in fixtures. Government addresses are high-value phishing targets even when published.

## IBAN

**IBAN Detected**

An International Bank Account Number was detected and it passes the ISO 13616 mod-97 checksum, so it is a structurally valid account identifier rather than a coincidental string. An IBAN names both the institution and the account, which is why it is used directly as a payment destination in SEPA and many other schemes.

*What to do:* An IBAN is a payment destination on its own — more directly actionable than a US routing number, which needs an account number beside it. Remove it from the file and supply it from a secret store. If it appeared in a public repository, tell the account holder: an IBAN is often all that is needed to initiate a direct debit.

*Short form (gitlab-sast):* Remove the IBAN and supply payment destinations from a secret store. An IBAN is directly actionable, so treat public exposure as an incident.

## IBM_CRN

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

*Short form (gitlab-sast):* Remove the CRN and supply resource identifiers from deployment configuration. They name real infrastructure, which helps an attacker map an environment and target it directly.

## IMAGE_METADATA

**Image Metadata Detected**

Metadata was detected in an image's EXIF, IPTC or XMP blocks. Depending on the capture device this can include GPS coordinates, a precise timestamp, a device serial number and the owner's name — none of it visible in the picture.

*What to do:* GPS coordinates are the field to check first: they can place a person at a location and time to within metres, and they survive most resizing and cropping. Strip metadata before publishing images, and be aware that a serial number links every photograph taken by the same camera.

*Short form (gitlab-sast):* Strip EXIF/IPTC/XMP before publishing images. GPS coordinates and device serial numbers survive resizing and are invisible in the picture.

## INSURANCE_MEMBER_ID

**Insurance Member ID Detected**

A health insurance member identifier was detected. Formats are payer-specific with no common checksum, so this is a contextual match. A member ID is the key used to look up coverage and claims, which is why it is a frequent target for medical identity theft.

*What to do:* Treat as PHI. Confirm the match against surrounding text, since payer formats vary widely. Member IDs combined with a name and date of birth are enough to attempt fraudulent claims.

*Short form (gitlab-sast):* Remove the member ID and handle it as PHI. Verify the match — payer formats vary, so detection is contextual.

## INTELLECTUAL_PROPERTY

**Potential Intellectual Property Detected**

Content that may contain intellectual property markers (copyright notices, trademarks, patents) was detected. This could indicate third-party IP that requires proper attribution or licensing.

*What to do:* Ensure that any third-party intellectual property is properly licensed and attributed. Review your organization's policies on using external code and content. If this is your organization's IP, ensure proper copyright notices are in place. For third-party content, verify compliance with license terms.

*Short form (gitlab-sast):* Review and remove proprietary information. Ensure compliance with intellectual property policies.

## IP_ADDRESS

**IP Address Detected**

An IP address was detected in the scanned content. IP addresses can be considered personally identifiable information under GDPR and other privacy regulations.

*What to do:* IP addresses are considered personal data under GDPR and similar regulations. Evaluate whether this IP address should be hardcoded. Consider using configuration files, environment variables, or service discovery mechanisms instead. If this is for testing, clearly document it as test data.

*Short form (gitlab-sast):* Remove IP addresses or replace with example addresses (e.g., 192.0.2.1).

## JCB

**JCB Card Number Detected**

A payment card number in the JCB range was detected. It passed the Luhn check digit and its issuer identification number (IIN) is one JCB issues. Primary account numbers are cardholder data under PCI DSS and must not be stored in source, logs or configuration.

*What to do:* If this is a real card number, treat it as a PCI DSS incident: remove it from the file AND from version-control history, then have the card reissued, because history rewriting does not recall a number an attacker may already have cloned. If it is test data, use the brand's published test numbers, which are Luhn-valid but declined by every processor.

*Short form (gitlab-sast):* Remove or mask credit card numbers. Consider using tokenization for legitimate payment processing needs.

## JWT_TOKEN

**JWT Detected Detected**

A JSON Web Token was detected. The header and payload are base64url-encoded, not encrypted, so any claims inside — subject, email, roles, tenant — are readable by anyone holding the token. The signature does not protect confidentiality, only integrity.

*What to do:* Read the payload before judging severity: it may itself contain PII, and the token authenticates as its subject until it expires. If it is live, revoke the session or rotate the signing key, and shorten token lifetimes. Never commit tokens as fixtures — mint one at test time instead, since a committed token teaches readers that checking one into source is acceptable.

*Short form (gitlab-sast):* Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.

## LAST_MODIFIED_BY

**Last-Modified-By Metadata Detected**

The last-modified-by property was detected in a document's metadata. It names the most recent editor, and because it updates on every save it often reveals a reviewer or approver who is not the stated author.

*What to do:* Frequently more revealing than the author field: it can expose who reviewed a document before release, and in a chain of edits it discloses internal workflow. Strip document properties before publishing.

*Short form (gitlab-sast):* Strip document properties before publication — this field can disclose reviewers and internal workflow.

## MASTERCARD

**Mastercard Card Number Detected**

A payment card number in the Mastercard range was detected. It passed the Luhn check digit and its issuer identification number (IIN) is one Mastercard issues. Primary account numbers are cardholder data under PCI DSS and must not be stored in source, logs or configuration.

*What to do:* If this is a real card number, treat it as a PCI DSS incident: remove it from the file AND from version-control history, then have the card reissued, because history rewriting does not recall a number an attacker may already have cloned. If it is test data, use the brand's published test numbers, which are Luhn-valid but declined by every processor.

*Short form (gitlab-sast):* Remove or mask credit card numbers. Consider using tokenization for legitimate payment processing needs.

## MEDICARE_MBI

**Medicare Beneficiary Identifier Detected**

A Medicare Beneficiary Identifier was detected and it matches the CMS format — eleven characters, position-specific letters and digits, with excluded letters that make coincidental matches unlikely. The MBI replaced the SSN-based HICN precisely so that a Medicare number would stop being an SSN, but it remains PHI and directly identifies a beneficiary.

*What to do:* Treat this as PHI under HIPAA. Remove it from the file and check whether it needs to be reported as a disclosure under your breach-assessment process; an MBI plus a name or date of birth is a strong identification.

*Short form (gitlab-sast):* Remove the MBI and handle it as PHI under HIPAA, including a breach assessment if it was exposed outside its intended audience.

## MRN

**Medical Record Number Detected**

A Medical Record Number was detected. MRNs are assigned per institution with no national format or checksum, so this is a contextual match — a nearby label is what distinguishes it from any other identifier. Within its issuing organisation an MRN is a direct patient key.

*What to do:* Treat as PHI. Because MRNs have no standard format, confirm the finding against the surrounding text before acting. An MRN is only meaningful to the issuing institution, which limits external misuse but not internal over-exposure.

*Short form (gitlab-sast):* Remove the MRN and handle it as PHI. Confirm the match first — MRNs have no standard format, so detection is contextual.

## NPI

**National Provider Identifier Detected**

A ten-digit National Provider Identifier was detected and it passes the CMS Luhn check. An NPI identifies a healthcare provider and is published in the NPPES public registry, so the number itself is not confidential — but it is a strong link between a record and a named clinician, which makes surrounding patient data far easier to attribute.

*What to do:* Lower urgency than patient identifiers, because the NPI is public. What matters is context: an NPI beside diagnoses, dates of service or patient identifiers turns a de-identified record into an attributable one, which affects whether a dataset still counts as de-identified.

*Short form (gitlab-sast):* Public in the NPPES registry, so rarely a disclosure alone. Review whether it re-identifies patient data held nearby.

## OCI_OCID

**Cloud Resource Identifier Detected**

A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.

*What to do:* Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.

*Short form (gitlab-sast):* Remove the OCID and supply resource identifiers from deployment configuration. They name real infrastructure, which helps an attacker map an environment and target it directly.

## OTPAUTH_URI

**OTP Provisioning URI Detected**

An otpauth:// provisioning URI was detected. This is the payload behind an authenticator QR code and it carries the shared TOTP secret in its query string, so it is enough to enrol a new device and generate valid codes indefinitely.

*What to do:* Treat it as a second-factor compromise: anyone with this URI can produce the same codes as the legitimate authenticator, and the user gets no signal that they are doing so. Re-enrol the account, which issues a fresh secret and invalidates this one.

*Short form (gitlab-sast):* Re-enrol the account to issue a new TOTP secret. The URI contains the shared secret, so it is a second-factor compromise rather than a configuration nit.

## OTP_SECRET

**OTP Shared Secret Detected**

A TOTP or HOTP shared secret was detected, typically base32-encoded. The secret is the entire basis of one-time-code generation: it does not expire and codes derived from it are indistinguishable from the legitimate user's.

*What to do:* Re-enrol the account so a new secret is issued. Storing a seed in source also means every environment that shares the file shares the second factor, which defeats per-user MFA.

*Short form (gitlab-sast):* Re-enrol to issue a new secret, and keep seeds in a secret manager. A committed seed makes the second factor shared rather than per-user.

## PASSPORT

**Passport Number Detected**

A passport number pattern was detected in the scanned content. Passport numbers are highly sensitive personally identifiable information that must be protected.

*What to do:* Passport numbers are protected under various privacy and identity theft prevention regulations. They should never be stored in source code or logs. Remove this passport number immediately and ensure it is stored in a secure, encrypted system with strict access controls and audit logging.

*Short form (gitlab-sast):* Remove the passport number. It is a government identity document number, cannot be reissued quickly, and supports identity theft rather than just profiling.

## PERSON_NAME

**Person Name Detected**

A person's name was detected in the scanned content. Names are considered personally identifiable information (PII) under various privacy regulations.

*What to do:* Person names are considered PII under GDPR, CCPA, and other privacy regulations. Evaluate whether this name should be present in the code. If it's test data, use clearly fictional names or anonymized identifiers. For production use, ensure names are stored securely with appropriate access controls and data retention policies.

*Short form (gitlab-sast):* Replace real names with obviously fictional ones. A name is a weak identifier alone but combines with a date of birth or address to identify an individual.

## PHONE

**Phone Number Detected**

A phone number was detected in the scanned content. Phone numbers can be considered personally identifiable information (PII) depending on context and jurisdiction.

*What to do:* Phone numbers may be considered PII under various privacy regulations. Evaluate whether this phone number should be present in the code. If it's for testing purposes, use clearly fake numbers (e.g., 555-0100 to 555-0199 in North America). For production use, store phone numbers in secure configuration systems with appropriate access controls.

*Short form (gitlab-sast):* Remove phone numbers or replace with example numbers (e.g., 555-0123).

## PO_BOX

**PO Box Address Detected**

A Post Office box address was detected. A PO box is a mail destination rather than a dwelling, so it reveals less than a street address — but it is still a contactable location tied to whoever rents it.

*What to do:* Lower sensitivity than a residential street address. Treat it as contact information: fine in published material, not something to accumulate in logs or test fixtures alongside names.

*Short form (gitlab-sast):* Usually lower risk than a street address. Avoid pairing it with names in logs or fixtures.

## RECOVERY_CODES

**Account Recovery Codes Detected**

Multi-factor recovery codes were detected. These are single-use bypasses for MFA, issued as a set, and each one is enough to complete an authentication without the second factor.

*What to do:* Recovery codes defeat the control that MFA exists to provide, so a leaked set reduces the account to password-only. Regenerate the codes, which invalidates the leaked set, and store them in a password manager rather than any file that could be committed or shared.

*Short form (gitlab-sast):* Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.

## SLACK_TOKEN

**Slack Token Detected**

A Slack token was detected. Slack tokens read and post as the user or app they belong to, so message history, channel membership and files in scope are all reachable.

*What to do:* Message history is often the most sensitive thing an organisation has in one place — treat a leaked token as disclosure of everything the token could read. Rotate it in the Slack app configuration and review the audit log for API calls you did not make.

*Short form (gitlab-sast):* Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.

## SSH_PRIVATE_KEY

**SSH Private Key Detected**

An SSH private key block was detected. If it is unencrypted — no passphrase — it is directly usable, and grants whatever access its matching public key has been authorised for on any host.

*What to do:* An unencrypted private key in a repository is a host-access credential, and the blast radius is every machine listing its public key in authorized_keys. Generate a new key pair, remove the old public key from every authorized_keys and deploy-key list, and keep private keys out of repositories entirely — use an agent or a certificate authority.

*Short form (gitlab-sast):* Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.

## SSN

**Social Security Number Detected**

A Social Security Number (SSN) pattern was detected in the scanned content. SSNs are highly sensitive personally identifiable information (PII) that must be protected under various regulations.

*What to do:* Social Security Numbers are protected under numerous regulations including GDPR, HIPAA, and various state privacy laws. SSNs should never be stored in source code, configuration files, or logs. Remove this SSN immediately and ensure it is stored in a secure, encrypted system with appropriate access controls. Consider implementing tokenization or other data protection mechanisms.

*Short form (gitlab-sast):* Remove Social Security Numbers from code and documentation. Use test data or anonymized identifiers instead.

## STRIPE_API_KEY

**Stripe API Key Detected**

A Stripe API key was detected. A live secret key can move money, read customer records and issue refunds; a restricted or test key is limited to what its configuration allows.

*What to do:* Check whether the prefix indicates a LIVE secret key — that is a financial and PII incident, not a hygiene one. Roll the key in the Stripe dashboard, which invalidates it immediately, then review recent API activity. Use restricted keys scoped to the endpoints a service actually calls.

*Short form (gitlab-sast):* Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.

## SWIFT_BIC

**SWIFT/BIC Code Detected**

A SWIFT/BIC business identifier code was detected — eight or eleven characters naming a financial institution and optionally a branch. Unlike an account number a BIC is public directory information, so on its own it is low sensitivity; it matters as corroboration that surrounding text is banking data.

*What to do:* A BIC alone rarely needs remediation. Treat it as a signal to look for account identifiers nearby: an IBAN or account number on the same record is the actual disclosure. If this is payment configuration, it still belongs in deployment configuration rather than in source.

*Short form (gitlab-sast):* Usually benign on its own — check for an account number or IBAN nearby, which would be the real disclosure. Keep payment configuration out of source.

## TEMPLATE_INFO

**Document Template Metadata Detected**

Template metadata was detected in a document's properties. It records the template the document was created from, frequently as a full filesystem path.

*What to do:* The path is the disclosure, not the template name: it can expose a username, an internal share name and a directory layout, all of which help an attacker map an internal environment. Strip document properties before publishing.

*Short form (gitlab-sast):* Strip document properties. Template paths often expose usernames and internal share layout.

## US_BANK_ACCOUNT

**US Bank Account Number Detected**

A US bank account number was detected. Account numbers have no checksum and no fixed length, so this is a contextual match — a nearby banking keyword is what distinguishes it from any other digit string. With a routing number it is sufficient to originate an ACH debit.

*What to do:* Confirm it against the surrounding text before acting, since account numbers cannot be validated structurally. If real, remove it and rotate the account if it has been exposed in a public repository; unlike a card, a bank account cannot be reissued quickly, so notify the account holder.

*Short form (gitlab-sast):* Remove the account number and supply banking details at deployment time. Account numbers cannot be validated structurally, so confirm the finding before closing it.

## US_MILITARY_ADDRESS

**US Military Address Detected**

A US military address was detected — an APO, FPO or DPO destination with an AA, AE or AP state code. These route mail to service members abroad or afloat.

*What to do:* Handle with more care than an ordinary address, not less: a military address indicates the addressee's affiliation and can imply deployment or location, which is information about the person beyond their contact details.

*Short form (gitlab-sast):* Remove military addresses. They disclose affiliation and can imply deployment, beyond ordinary contact information.

## US_RURAL_ROUTE

**US Rural Route Address Detected**

A US rural route or highway contract route address was detected. These identify a delivery route and box rather than a street, and are used where street addressing is absent.

*What to do:* Treat as a residential address. Rural routes cover sparsely populated areas, so a route and box number can be MORE identifying than a street address in a city, not less.

*Short form (gitlab-sast):* Treat as residential. In sparsely populated areas a route and box number is highly identifying.

## US_STREET_ADDRESS

**US Street Address Detected**

A US street address was detected — a number, a street name and a recognised street-type suffix. An address is personal data when it is a residence, and it is a strong quasi-identifier: address with a surname identifies a household.

*What to do:* Distinguish a residential address from a business one, which is usually published and needs no remediation. If residential, it is personal data under GDPR and CCPA and belongs in a system with access control, not in source or logs.

*Short form (gitlab-sast):* Remove residential addresses; business addresses are usually public. Address plus surname identifies a household.

## VIN

**Vehicle Identification Number Detected**

A Vehicle Identification Number (VIN) was detected in the scanned content. VINs can be used to identify vehicle owners and access personal information such as registration, insurance, and accident history.

*What to do:* VINs are linked to vehicle owner identity and can reveal personal information through public databases. They should not be stored in source code or logs. Remove VINs and use anonymized identifiers for testing. For production systems, store VINs in encrypted databases with appropriate access controls.

*Short form (gitlab-sast):* Remove Vehicle Identification Numbers from code and documentation. VINs can be used to identify vehicle owners and their personal information.

## VISA

**Visa Card Number Detected**

A payment card number in the Visa range was detected. It passed the Luhn check digit and its issuer identification number (IIN) is one Visa issues. Primary account numbers are cardholder data under PCI DSS and must not be stored in source, logs or configuration.

*What to do:* If this is a real card number, treat it as a PCI DSS incident: remove it from the file AND from version-control history, then have the card reissued, because history rewriting does not recall a number an attacker may already have cloned. If it is test data, use the brand's published test numbers, which are Luhn-valid but declined by every processor.

*Short form (gitlab-sast):* Remove or mask credit card numbers. Consider using tokenization for legitimate payment processing needs.

