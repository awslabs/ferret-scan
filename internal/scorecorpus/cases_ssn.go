// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

// SSNCases is the gated SSN corpus: 115 documents carrying 155 labels, of which 15
// are negative cases.
//
// 24 of those documents were quarantined until 2026-08-05, when their polarity was
// settled: they carry an SSN-shaped value under an honest header for a NON-US
// national identifier (sin, nino, personnummer, codice fiscale) or a generic
// government one (national_id, govt_id, id_number, tin). They are true positives --
// see the note on SSNUndecided below for the reasoning and the measured effect.
//
// Ground truth is derived from the bytes PLANTED in each fixture, never from what
// the scanner currently reports — otherwise the corpus would certify today's
// behavior as correct by construction. Only three distinct SSN values appear
// across the whole corpus (130-07-5728, 214-89-6712, 301-45-7788, plus
// separator-less and space-separated forms of each), so every label is traceable
// to a value a human placed deliberately.
//
// MinBand records the band the value reaches today and is the ratchet floor. The
// LABEL's existence is ground truth; its band is a measurement. One label sits at
// BandLow on purpose: a bare 9-digit run with no context scores 50, and that is
// defensible — but it must still be REPORTED, because redaction is
// confidence-blind and a LOW finding is still masked (measured: *****5728).
//
// Negative cases carry an SSN-shaped value under a column header that names it as
// something else (tracking_number, order_id, zip_code, phone, quantity). Every one
// of them is detected at HIGH today: 45 false positives, baselined as a known defect
// so a later precision fix can be measured rather than argued. That is the distinction
// the promoted 24 turn on -- "personnummer" names the value as a government
// identifier, "tracking_number" names it as something that is not PII at all.
var SSNCases = []Case{
	{
		Name:      "c01_genuine_ssn_header",
		Origin:    "harvested c01_genuine_ssn_header.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,ssn\n" +
			"Jane Smith,Payroll,130-07-5728\n" +
			"Bob Jones,IT,214-89-6712\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c02_no_header_at_all",
		Origin:    "harvested c02_no_header_at_all.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "Jane Smith,Payroll,130-07-5728\n" +
			"Bob Jones,IT,214-89-6712\n" +
			"Amy Lee,Legal,301-45-7788\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 2, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c03_blank_ssn_header",
		Origin:    "harvested c03_blank_ssn_header.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,\n" +
			"Jane Smith,Payroll,130-07-5728\n" +
			"Bob Jones,IT,214-89-6712\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c04_tsv",
		Origin:    "harvested c04_tsv.tsv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name\tdept\tssn\n" +
			"Jane Smith\tPayroll\t130-07-5728\n" +
			"Bob Jones\tIT\t214-89-6712\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c05_semicolon_eu",
		Origin:    "harvested c05_semicolon_eu.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name;dept;ssn\n" +
			"Jane Smith;Payroll;130-07-5728\n" +
			"Bob Jones;IT;214-89-6712\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c06_pipe",
		Origin:    "harvested c06_pipe.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name|dept|ssn\n" +
			"Jane Smith|Payroll|130-07-5728\n" +
			"Bob Jones|IT|214-89-6712\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c07_fixed_width",
		Origin:    "harvested c07_fixed_width.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "NAME            DEPT      SSN\n" +
			"Jane Smith      Payroll   130-07-5728\n" +
			"Bob Jones       IT        214-89-6712\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c08_two_line_header",
		Origin:    "harvested c08_two_line_header.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "Employee,Department,Social\n" +
			"Name,Name,Security Number\n" +
			"Jane Smith,Payroll,130-07-5728\n" +
			"Bob Jones,IT,214-89-6712\n",
		Labels: []Label{
			{Line: 3, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c09_quoted_header_with_delim",
		Origin:    "harvested c09_quoted_header_with_delim.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "\"Name, Full\",dept,\"SSN, primary\"\n" +
			"\"Smith, Jane\",Payroll,130-07-5728\n" +
			"\"Jones, Bob\",IT,214-89-6712\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c10_bare9_ssn_header",
		Origin:    "harvested c10_bare9_ssn_header.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,ssn\n" +
			"Jane Smith,Payroll,130075728\n" +
			"Bob Jones,IT,214896712\n",
		Labels: []Label{
			{Line: 2, Value: "130075728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214896712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c11_preamble_comment",
		Origin:    "harvested c11_preamble_comment.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "# export 2026-01-01\n" +
			"# confidential\n" +
			"name,dept,ssn\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 4, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c12_ragged_rows",
		Origin:    "harvested c12_ragged_rows.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,ssn\n" +
			"Jane Smith,Payroll,130-07-5728\n" +
			"Bob Jones,IT\n" +
			"Amy,Legal,301-45-7788,extra,more\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c13_two_field_only",
		Origin:    "harvested c13_two_field_only.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "ssn,name\n" +
			"130-07-5728,Jane Smith\n" +
			"214-89-6712,Bob Jones\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandMedium},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandMedium},
		},
		Redactable: true,
	},
	{
		Name:      "c14_trailing_header_only",
		Origin:    "harvested c14_trailing_header_only.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "ssn\n" +
			"130-07-5728\n" +
			"214-89-6712\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandMedium},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandMedium},
		},
		Redactable: true,
	},
	{
		Name:      "c29_header_ssn_but_col_shift",
		Origin:    "harvested c29_header_ssn_but_col_shift.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,ssn,notes\n" +
			"Jane Smith,130-07-5728,see file\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c30_ssn_in_notes_column",
		Origin:    "harvested c30_ssn_in_notes_column.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,notes\n" +
			"Jane Smith,Payroll,\"employee SSN is 130-07-5728\"\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c31_ssn_in_freetext_col",
		Origin:    "harvested c31_ssn_in_freetext_col.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "ticket,priority,description\n" +
			"T-1,high,Customer gave SSN 130-07-5728 over the phone\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c32_crlf_ssn_header",
		Origin:    "harvested c32_crlf_ssn_header.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,ssn\r\n" +
			"Jane Smith,Payroll,130-07-5728\r\n" +
			"Bob Jones,IT,214-89-6712\r\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c33_bom_ssn_header",
		Origin:    "harvested c33_bom_ssn_header.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "\ufeffname,dept,ssn\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c34_quoted_values",
		Origin:    "harvested c34_quoted_values.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,ssn\n" +
			"\"Jane Smith\",\"Payroll\",\"130-07-5728\"\n" +
			"\"Bob Jones\",\"IT\",\"214-89-6712\"\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c35_data_row_wider",
		Origin:    "harvested c35_data_row_wider.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept\n" +
			"Jane Smith,Payroll,130-07-5728\n" +
			"Bob Jones,IT,214-89-6712\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c36_header_row_wider",
		Origin:    "harvested c36_header_row_wider.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,ssn,notes,extra\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c37_excel_semicolon_crlf",
		Origin:    "harvested c37_excel_semicolon_crlf.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "namn;avdelning;personnummer\r\n" +
			"Jane Smith;Lon;130-07-5728\r\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c38_ssn_first_col",
		Origin:    "harvested c38_ssn_first_col.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "ssn,name,dept\n" +
			"130-07-5728,Jane Smith,Payroll\n" +
			"214-89-6712,Bob Jones,IT\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c39_blank_first_line",
		Origin:    "harvested c39_blank_first_line.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "\n" +
			"name,dept,ssn\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 3, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c40_title_then_header",
		Origin:    "harvested c40_title_then_header.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "Employee Roster Export 2026\n" +
			"name,dept,ssn\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 3, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c41_all_numeric_header",
		Origin:    "harvested c41_all_numeric_header.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "1,2,3\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c42_uppercase_header",
		Origin:    "harvested c42_uppercase_header.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "NAME,DEPT,SSN\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c43_spaces_in_header",
		Origin:    "harvested c43_spaces_in_header.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "Full Name , Department , Social Security Number \n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c44_no_header_bare9",
		Origin:    "harvested c44_no_header_bare9.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "Emp001,Payroll,130075728\n" +
			"Emp002,IT,214896712\n" +
			"Emp003,Legal,301457788\n",
		Labels: []Label{
			{Line: 1, Value: "130075728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 2, Value: "214896712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "301457788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c45_tsv_no_header",
		Origin:    "harvested c45_tsv_no_header.tsv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "Emp001\tPayroll\t130-07-5728\n" +
			"Emp002\tIT\t214-89-6712\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 2, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c46_pipe_no_header",
		Origin:    "harvested c46_pipe_no_header.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "Emp001|Payroll|130-07-5728\n" +
			"Emp002|IT|214-89-6712\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 2, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c47_bom_ssn_first_col",
		Origin:    "harvested c47_bom_ssn_first_col.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "\ufeffssn,name,dept\n" +
			"130-07-5728,Jane Smith,Payroll\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:   "c48_header_only_row",
		Origin: "harvested c48_header_only_row.csv (session 2026-08)",
		Rationale: "A header naming an SSN column with NO data row beneath it contains no SSN " +
			"at all. The header word must not conjure a finding out of nothing, which makes " +
			"this the control proving the positive cases earn their labels from the VALUE " +
			"rather than from a nearby column name.",
		Checks:     []string{"SSN"},
		Input:      "ssn,name,dept\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "c49_ssn_in_header_row",
		Origin:    "harvested c49_ssn_in_header_row.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "130-07-5728,name,dept\n" +
			"Jane,Payroll,x\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p01_sentence_terminal_period",
		Origin:    "harvested p01_sentence_terminal_period.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "Employee SSN: 130-07-5728.\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p02_comma",
		Origin:    "harvested p02_comma.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "The SSN is 130-07-5728, on file since 2019.\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p03_semicolon",
		Origin:    "harvested p03_semicolon.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "ssn: 130-07-5728; verified\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p04_colon_after",
		Origin:    "harvested p04_colon_after.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "Employee SSN 130-07-5728: verified by HR\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p05_exclamation",
		Origin:    "harvested p05_exclamation.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "Confirmed SSN 130-07-5728!\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p06_question",
		Origin:    "harvested p06_question.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "Is the employee SSN 130-07-5728?\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p07_paren",
		Origin:    "harvested p07_paren.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "Employee SSN (130-07-5728) verified.\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p08_dquote",
		Origin:    "harvested p08_dquote.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "The employee's SSN is \"130-07-5728\".\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p09_squote",
		Origin:    "harvested p09_squote.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "Her SSN is '130-07-5728'.\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p10_bracket",
		Origin:    "harvested p10_bracket.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "Employee SSN [130-07-5728] approved.\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p11_no_trailing_newline",
		Origin:    "harvested p11_no_trailing_newline.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "Employee SSN: 130-07-5728",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p12_bare_terminal_period",
		Origin:    "harvested p12_bare_terminal_period.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "Employee record: the SSN is 130075728.\n",
		Labels: []Label{
			{Line: 1, Value: "130075728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p13_spaced_terminal_period",
		Origin:    "harvested p13_spaced_terminal_period.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "Social Security Number: 130 07 5728.\n",
		Labels: []Label{
			{Line: 1, Value: "130 07 5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p14_kv_terminal",
		Origin:    "harvested p14_kv_terminal.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "ssn=130075728.\n",
		Labels: []Label{
			{Line: 1, Value: "130075728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p15_slash",
		Origin:    "harvested p15_slash.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "SSN/TIN: 130-07-5728/US\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p16_em_dash",
		Origin:    "harvested p16_em_dash.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "Employee SSN \u2014 130-07-5728 \u2014 on record.\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p17_tab_label",
		Origin:    "harvested p17_tab_label.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "SSN\t130-07-5728\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p18_trailing_ellipsis",
		Origin:    "harvested p18_trailing_ellipsis.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "SSN: 130-07-5728...\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p19_end_paren_period",
		Origin:    "harvested p19_end_paren_period.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "(Employee SSN: 130-07-5728.)\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "p20_multiline_prose",
		Origin:    "harvested p20_multiline_prose.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "Dear HR,\n" +
			"\n" +
			"Please update the record. The employee SSN is 130-07-5728.\n" +
			"Thank you.\n",
		Labels: []Label{
			{Line: 3, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "s01_json",
		Origin:    "harvested s01_json.json (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "{\n" +
			"  \"name\": \"Jane Smith\",\n" +
			"  \"ssn\": \"130-07-5728\",\n" +
			"  \"dept\": \"Payroll\"\n" +
			"}\n",
		Labels: []Label{
			{Line: 3, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "s02_json_oneline",
		Origin:    "harvested s02_json_oneline.json (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "{\"name\":\"Jane Smith\",\"ssn\":\"130-07-5728\",\"dept\":\"Payroll\",\"id\":7}\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "s03_json_array",
		Origin:    "harvested s03_json_array.json (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "[{\"n\":\"a\",\"ssn\":\"130-07-5728\"},{\"n\":\"b\",\"ssn\":\"214-89-6712\"}]\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 1, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "s04_yaml",
		Origin:    "harvested s04_yaml.yaml (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "employee:\n" +
			"  name: Jane Smith\n" +
			"  ssn: 130-07-5728\n" +
			"  dept: Payroll\n",
		Labels: []Label{
			{Line: 3, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "s05_yaml_inline",
		Origin:    "harvested s05_yaml_inline.yaml (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "employee: {name: Jane Smith, ssn: 130-07-5728, dept: Payroll}\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "s06_log_commas",
		Origin:    "harvested s06_log_commas.log (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "2026-01-01T10:00:00Z,INFO,api,POST,/enroll,200,45ms,ssn=130-07-5728,ok\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "s07_log_bracket",
		Origin:    "harvested s07_log_bracket.log (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "2026-01-01 10:00:00 [INFO] enroll: ssn=130-07-5728 status=ok dur=45ms\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "s08_markdown_table",
		Origin:    "harvested s08_markdown_table.md (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "| Name | Dept | SSN |\n" +
			"|------|------|-----|\n" +
			"| Jane Smith | Payroll | 130-07-5728 |\n" +
			"| Bob Jones | IT | 214-89-6712 |\n",
		Labels: []Label{
			{Line: 3, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "s09_html_table",
		Origin:    "harvested s09_html_table.html (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "<table>\n" +
			"<tr><th>Name</th><th>Dept</th><th>SSN</th></tr>\n" +
			"<tr><td>Jane Smith</td><td>Payroll</td><td>130-07-5728</td></tr>\n" +
			"</table>\n",
		Labels: []Label{
			{Line: 3, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "s10_xml",
		Origin:    "harvested s10_xml.xml (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "<employees>\n" +
			"  <employee><name>Jane Smith</name><ssn>130-07-5728</ssn></employee>\n" +
			"</employees>\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "s11_sql_insert",
		Origin:    "harvested s11_sql_insert.sql (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "INSERT INTO employees (name, dept, ssn) VALUES ('Jane Smith', 'Payroll', '130-07-5728');\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "s12_ini",
		Origin:    "harvested s12_ini.ini (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "[employee]\n" +
			"name = Jane Smith\n" +
			"ssn = 130-07-5728\n",
		Labels: []Label{
			{Line: 3, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "s13_form_layout",
		Origin:    "harvested s13_form_layout.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "EMPLOYEE INTAKE FORM\n" +
			"\n" +
			"Name:  Jane Smith\n" +
			"SSN:   130-07-5728\n" +
			"Dept:  Payroll\n",
		Labels: []Label{
			{Line: 4, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "s14_bare_ssn_alone",
		Origin:    "harvested s14_bare_ssn_alone.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "130-07-5728\n",
		Labels: []Label{
			{Line: 1, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandMedium},
		},
		Redactable: true,
	},
	{
		Name:      "s15_bare9_alone",
		Origin:    "harvested s15_bare9_alone.txt (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input:     "130075728\n",
		Labels: []Label{
			{Line: 1, Value: "130075728", Types: []string{"SSN"}, MinBand: BandLow},
		},
		Redactable: true,
	},
	{
		Name:      "tp__employee_ssn",
		Origin:    "harvested TP__employee_ssn.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,employee_ssn,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "tp__member_ssn",
		Origin:    "harvested TP__member_ssn.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,member_ssn,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "tp__social_security_number",
		Origin:    "harvested TP__social_security_number.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,social_security_number,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "tp__ssn",
		Origin:    "harvested TP__ssn.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,ssn,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "tp__tax_id",
		Origin:    "harvested TP__tax_id.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,tax_id,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "tp__taxpayer_id",
		Origin:    "harvested TP__taxpayer_id.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,taxpayer_id,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "fp__account_number",
		Origin:    "harvested FP__account_number.csv (session 2026-08)",
		Rationale: "A column headed 'account_number' holds an SSN-shaped value that is not an SSN. Detecting it at HIGH is a false positive that trains reviewers to ignore the tool.",
		Checks:    []string{"SSN"},
		Input: "a,account_number,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "fp__barcode",
		Origin:    "harvested FP__barcode.csv (session 2026-08)",
		Rationale: "A column headed 'barcode' holds an SSN-shaped value that is not an SSN. Detecting it at HIGH is a false positive that trains reviewers to ignore the tool.",
		Checks:    []string{"SSN"},
		Input: "a,barcode,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "fp__invoice_number",
		Origin:    "harvested FP__invoice_number.csv (session 2026-08)",
		Rationale: "A column headed 'invoice_number' holds an SSN-shaped value that is not an SSN. Detecting it at HIGH is a false positive that trains reviewers to ignore the tool.",
		Checks:    []string{"SSN"},
		Input: "a,invoice_number,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "fp__order_id",
		Origin:    "harvested FP__order_id.csv (session 2026-08)",
		Rationale: "A column headed 'order_id' holds an SSN-shaped value that is not an SSN. Detecting it at HIGH is a false positive that trains reviewers to ignore the tool.",
		Checks:    []string{"SSN"},
		Input: "a,order_id,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "fp__part_number",
		Origin:    "harvested FP__part_number.csv (session 2026-08)",
		Rationale: "A column headed 'part_number' holds an SSN-shaped value that is not an SSN. Detecting it at HIGH is a false positive that trains reviewers to ignore the tool.",
		Checks:    []string{"SSN"},
		Input: "a,part_number,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "fp__phone",
		Origin:    "harvested FP__phone.csv (session 2026-08)",
		Rationale: "A column headed 'phone' holds an SSN-shaped value that is not an SSN. Detecting it at HIGH is a false positive that trains reviewers to ignore the tool.",
		Checks:    []string{"SSN"},
		Input: "a,phone,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "fp__product_code",
		Origin:    "harvested FP__product_code.csv (session 2026-08)",
		Rationale: "A column headed 'product_code' holds an SSN-shaped value that is not an SSN. Detecting it at HIGH is a false positive that trains reviewers to ignore the tool.",
		Checks:    []string{"SSN"},
		Input: "a,product_code,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "fp__quantity",
		Origin:    "harvested FP__quantity.csv (session 2026-08)",
		Rationale: "A column headed 'quantity' holds an SSN-shaped value that is not an SSN. Detecting it at HIGH is a false positive that trains reviewers to ignore the tool.",
		Checks:    []string{"SSN"},
		Input: "a,quantity,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "fp__routing_number",
		Origin:    "harvested FP__routing_number.csv (session 2026-08)",
		Rationale: "A column headed 'routing_number' holds an SSN-shaped value that is not an SSN. Detecting it at HIGH is a false positive that trains reviewers to ignore the tool.",
		Checks:    []string{"SSN"},
		Input: "a,routing_number,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "fp__serial_number",
		Origin:    "harvested FP__serial_number.csv (session 2026-08)",
		Rationale: "A column headed 'serial_number' holds an SSN-shaped value that is not an SSN. Detecting it at HIGH is a false positive that trains reviewers to ignore the tool.",
		Checks:    []string{"SSN"},
		Input: "a,serial_number,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "fp__sku",
		Origin:    "harvested FP__sku.csv (session 2026-08)",
		Rationale: "A column headed 'sku' holds an SSN-shaped value that is not an SSN. Detecting it at HIGH is a false positive that trains reviewers to ignore the tool.",
		Checks:    []string{"SSN"},
		Input: "a,sku,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "fp__tracking_number",
		Origin:    "harvested FP__tracking_number.csv (session 2026-08)",
		Rationale: "A column headed 'tracking_number' holds an SSN-shaped value that is not an SSN. Detecting it at HIGH is a false positive that trains reviewers to ignore the tool.",
		Checks:    []string{"SSN"},
		Input: "a,tracking_number,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "fp__transaction_id",
		Origin:    "harvested FP__transaction_id.csv (session 2026-08)",
		Rationale: "A column headed 'transaction_id' holds an SSN-shaped value that is not an SSN. Detecting it at HIGH is a false positive that trains reviewers to ignore the tool.",
		Checks:    []string{"SSN"},
		Input: "a,transaction_id,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "fp__widget_count",
		Origin:    "harvested FP__widget_count.csv (session 2026-08)",
		Rationale: "A column headed 'widget_count' holds an SSN-shaped value that is not an SSN. Detecting it at HIGH is a false positive that trains reviewers to ignore the tool.",
		Checks:    []string{"SSN"},
		Input: "a,widget_count,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "fp__zip_code",
		Origin:    "harvested FP__zip_code.csv (session 2026-08)",
		Rationale: "A column headed 'zip_code' holds an SSN-shaped value that is not an SSN. Detecting it at HIGH is a false positive that trains reviewers to ignore the tool.",
		Checks:    []string{"SSN"},
		Input: "a,zip_code,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "c15_honest_sin",
		Origin:    "harvested c15_honest_sin.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,sin\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c16_honest_tin",
		Origin:    "harvested c16_honest_tin.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,tin\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c17_honest_id_number",
		Origin:    "harvested c17_honest_id_number.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,id_number\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c18_honest_national_id",
		Origin:    "harvested c18_honest_national_id.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,national_id\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c19_honest_member_id",
		Origin:    "harvested c19_honest_member_id.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,plan,member_id\n" +
			"Jane Smith,Gold,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c20_honest_participant_id",
		Origin:    "harvested c20_honest_participant_id.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,plan,participant_id\n" +
			"Jane Smith,401k,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c21_honest_taxpayer",
		Origin:    "harvested c21_honest_taxpayer.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,taxpayer\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c22_honest_nino",
		Origin:    "harvested c22_honest_nino.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,nino\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c23_honest_personnummer",
		Origin:    "harvested c23_honest_personnummer.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "namn,avdelning,personnummer\n" +
			"Jane Smith,Lon,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c24_honest_employee_number",
		Origin:    "harvested c24_honest_employee_number.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,employee number\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c25_honest_ss_abbrev",
		Origin:    "harvested c25_honest_ss_abbrev.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,ss#\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c26_honest_socsec",
		Origin:    "harvested c26_honest_socsec.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,socsec\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c27_honest_govt_id",
		Origin:    "harvested c27_honest_govt_id.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,govt_id\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "c28_honest_fiscal_code",
		Origin:    "harvested c28_honest_fiscal_code.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "name,dept,codice_fiscale\n" +
			"Jane Smith,Payroll,130-07-5728\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "tp__employee_number",
		Origin:    "harvested TP__employee_number.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,employee number,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "tp__govt_id",
		Origin:    "harvested TP__govt_id.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,govt_id,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "tp__id_number",
		Origin:    "harvested TP__id_number.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,id_number,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "tp__national_id",
		Origin:    "harvested TP__national_id.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,national_id,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "tp__nino",
		Origin:    "harvested TP__nino.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,nino,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "tp__participant_id",
		Origin:    "harvested TP__participant_id.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,participant_id,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "tp__personnummer",
		Origin:    "harvested TP__personnummer.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,personnummer,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "tp__sin",
		Origin:    "harvested TP__sin.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,sin,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "tp__socsec",
		Origin:    "harvested TP__socsec.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,socsec,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "tp__tin",
		Origin:    "harvested TP__tin.csv (session 2026-08)",
		Rationale: "Real-world layout that must not hide an SSN from the redactor.",
		Checks:    []string{"SSN"},
		Input: "a,tin,c\n" +
			"x1,130-07-5728,y\n" +
			"x2,214-89-6712,y\n" +
			"x3,301-45-7788,y\n",
		Labels: []Label{
			{Line: 2, Value: "130-07-5728", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 3, Value: "214-89-6712", Types: []string{"SSN"}, MinBand: BandHigh},
			{Line: 4, Value: "301-45-7788", Types: []string{"SSN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
}

// SSNUndecided is empty: the polarity question it existed for has been ANSWERED.
//
// It formerly held 24 fixtures carrying an SSN-shaped value under an honest header
// for a non-US national identifier -- sin (Canada), nino (UK), personnummer
// (Sweden), codice fiscale (Italy) -- or a generic government one (id_number,
// national_id, govt_id, employee_number, participant_id, socsec, tin, taxpayer).
// All 24 are detected today, 45 of their 46 findings at HIGH, and all are redacted.
//
// Maintainer decision (2026-08-05): they are TRUE POSITIVES, and they are now
// scored. Three reasons, in order of weight:
//
//  1. The validator was BUILT for them. Its own positiveKeywords list includes
//     "national id", "government id", "federal id", "tax id", "personal id" and
//     "identification number" -- none of which are US Social Security terms. The
//     current behavior is intent, not accident.
//  2. A DLP tool's job is masking government identifiers, not adjudicating which
//     country issued them. A Swedish personnummer under a "personnummer" header is
//     exactly as sensitive as a US SSN under an "ssn" header.
//  3. Labelling them false positives would make DELETING real detections of real
//     PII score as an improvement. A gate that rewards leaking is worse than no
//     gate at all. The two options were not symmetric.
//
// The cost is deliberate and is the actual substance of the decision: the SSN
// recall floor rises from 111 to 155, so these 44 findings can never be silently
// dropped without failing the gate.
//
// Measured effect on the headline number: SSN precision 0.7115 (excluded) ->
// 0.7750 (as TP). Had they been labelled FP it would have been 0.5550.
//
// The list is kept (rather than deleted) as the designated home for shapes whose
// correct polarity is genuinely unsettled. Its size is baselined, so adding one is
// a visible, explained change and not a quiet way to drop a failing case.
var SSNUndecided = []Case{}
