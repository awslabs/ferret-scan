// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

// technicalAdjectivesMap for O(1) lookups of technical adjectives
var technicalAdjectivesMap = map[string]bool{
	"manual":      true,
	"automatic":   true,
	"automated":   true,
	"primary":     true,
	"secondary":   true,
	"backup":      true,
	"test":        true,
	"production":  true,
	"staging":     true,
	"development": true,
	"local":       true,
	"remote":      true,
	"public":      true,
	"private":     true,
	"internal":    true,
	"external":    true,
	"global":      true,
	"regional":    true,
	"cross":       true,
	"multi":       true,
	"single":      true,
	"dual":        true,
	"max":         true,
	"min":         true,
	"bulk":        true,
	"batch":       true,
}

// technicalNounsMap for O(1) lookups of technical nouns
var technicalNounsMap = map[string]bool{
	"execution":      true,
	"deployment":     true,
	"testing":        true,
	"configuration":  true,
	"management":     true,
	"operations":     true,
	"monitoring":     true,
	"logging":        true,
	"auditing":       true,
	"validation":     true,
	"verification":   true,
	"processing":     true,
	"handling":       true,
	"control":        true,
	"access":         true,
	"security":       true,
	"authentication": true,
	"authorization":  true,
	"key":            true,
	"keys":           true,
	"session":        true,
	"connection":     true,
	"transaction":    true,
	"query":          true,
	"request":        true,
	"response":       true,
	"event":          true,
	"message":        true,
	"notification":   true,
	"alert":          true,
	"error":          true,
	"exception":      true,
	"failure":        true,
	"timeout":        true,
	"service":        true,
	"component":      true,
	"module":         true,
	"function":       true,
	"method":         true,
	"procedure":      true,
	"algorithm":      true,
	"pattern":        true,
	"template":       true,
	"schema":         true,
	"model":          true,
}

// technicalTermsMap consolidates all technical terms, business patterns, and common phrases for O(1) lookups
var technicalTermsMap = map[string]bool{
	// Multi-word technical phrases
	"manual execution":                true,
	"test cross":                      true,
	"primary key":                     true,
	"max concurrency":                 true,
	"max errors":                      true,
	"manual testing":                  true,
	"manual deployment":               true,
	"manual operations":               true,
	"manual intervention":             true,
	"manual member":                   true,
	"manual executions":               true,
	"bulk cross":                      true,
	"centralized logging":             true,
	"use case":                        true,
	"test case":                       true,
	"cross account":                   true,
	"member account":                  true,
	"logging account":                 true,
	"management account":              true,
	"current account":                 true,
	"target account":                  true,
	"administrator account":           true,
	"delegated administrator account": true,
	"manual execution auditor":        true,
	"member account execution role":   true,
	"member account validation":       true,
	"manual member account setup":     true,
	"manual member account":           true,
	"resource groups":                 true,
	"git repository":                  true,
	"git repo":                        true,
	"customer log":                    true,
	"customer audit":                  true,
	"log archive":                     true,
	"customer log archive":            true,
	"member accounts":                 true,
	"logging accounts":                true,
	"target host":                     true,
	"output name":                     true,
	"current value":                   true,
	"document name":                   true,
	"trust role":                      true,
	"dry run":                         true,
	"authorization tracking":          true,
	"critical security":               true,
	"account structure":               true,
	"validation dashboard":            true,
	"verify environment":              true,
	"delegated administrator":         true,
	"execution role":                  true,
	"account validation":              true,
	"environment validation":          true,
	"security validation":             true,
	"structure validation":            true,
	"run validation":                  true,
	"dry run v":                       true,
	"critical security v":             true,
	"account structure v":             true,
	"verify environment v":            true,
	"auto scaling":                    true,
	"load balancer":                   true,
	"api gateway":                     true,
	"lambda function":                 true,
	"cloud formation":                 true,
	"machine learning":                true,
	"artificial intelligence":         true,
	"data science":                    true,
	"big data":                        true,
	"software engineering":            true,
	"system administration":           true,
	"network security":                true,
	"database management":             true,
	"web development":                 true,
	"mobile development":              true,
	"quality assurance":               true,
	"user interface":                  true,
	"user experience":                 true,
	"business logic":                  true,
	"version control":                 true,
	"continuous integration":          true,
	"continuous deployment":           true,
	"infrastructure code":             true,
	"configuration management":        true,
	"monitoring system":               true,
	"logging framework":               true,
	"testing framework":               true,
	"development environment":         true,
	"production environment":          true,
	"staging environment":             true,
	"file system":                     true,
	"operating system":                true,
	"command line":                    true,
	"graphical interface":             true,
	"network protocol":                true,
	"security protocol":               true,
	"authentication system":           true,
	"authorization system":            true,
	"access control":                  true,
	"permission system":               true,
	"backup system":                   true,
	"recovery system":                 true,
	"disaster recovery":               true,
	"project management":              true,
	"task management":                 true,
	"resource management":             true,
	"change management":               true,
	"release management":              true,
	"incident management":             true,

	// Business and corporate terms - reference businessPatternsMap to avoid duplication
	// Keeping only terms unique to technical contexts

	// Single word technical terms (consolidated from technicalNounsMap)
	"execution":      true,
	"deployment":     true,
	"testing":        true,
	"configuration":  true,
	"management":     true,
	"operations":     true,
	"monitoring":     true,
	"logging":        true,
	"auditing":       true,
	"validation":     true,
	"verification":   true,
	"processing":     true,
	"handling":       true,
	"control":        true,
	"access":         true,
	"security":       true,
	"authentication": true,
	"authorization":  true,
	"key":            true,
	"keys":           true,
	"session":        true,
	"connection":     true,
	"transaction":    true,
	"query":          true,
	"request":        true,
	"response":       true,
	"event":          true,
	"message":        true,
	"notification":   true,
	"alert":          true,
	"error":          true,
	"exception":      true,
	"failure":        true,
	"timeout":        true,
	"service":        true,
	"component":      true,
	"module":         true,
	"function":       true,
	"method":         true,
	"procedure":      true,
	"algorithm":      true,
	"pattern":        true,
	"template":       true,
	"schema":         true,
	"model":          true,
}

// veryCommonNamesMap for O(1) lookups of very common names that often appear in technical contexts
// Only includes terms unique to this map (duplicates with other maps removed)
var veryCommonNamesMap = map[string]bool{
	"use":       true,
	"case":      true,
	"admin":     true,
	"user":      true,
	"guest":     true,
	"default":   true,
	"system":    true,
	"main":      true,
	"root":      true,
	"temp":      true,
	"temporary": true,
	"example":   true,
	"sample":    true,
	"demo":      true,
	"trial":     true,
	"beta":      true,
	"alpha":     true,
	"dev":       true,
	"prod":      true,
	"install":   true,
	"update":    true,
	"upgrade":   true,
	"fix":       true,
	"bug":       true,
	"issue":     true,
	"warning":   true,
	"info":      true,
	"debug":     true,
	"trace":     true,
	"check":     true,
	"confirm":   true,
	"approve":   true,
	"reject":    true,
	"cancel":    true,
	"abort":     true,
	"stop":      true,
	"start":     true,
	"run":       true,
	"operate":   true,
}

// commonWordNamesMap holds tokens that are BOTH common English words AND present
// in the first/last name databases (will/read, mark/brown, grace/hill, ...). A
// Title-Cased bigram whose two tokens are both in this set ("Will Read", "Mark
// Brown", "Grace Hill") is far more often ordinary prose/headings than a person
// name, yet the both-names-known path scored it 90-100 (HIGH). When BOTH tokens
// are in this set and there is no corroborating name signal (formal pattern,
// title, suffix, comma form, or context keyword), the score is held at MEDIUM
// instead of HIGH. A real name needs only one distinctive (non-dictionary) token
// to stay HIGH, so this does not demote names like "John Smith" or "David Brown".
var commonWordNamesMap = map[string]bool{
	// first-name-like common words
	"will": true, "mark": true, "grace": true, "may": true, "june": true,
	"april": true, "art": true, "bill": true, "rose": true, "hope": true,
	"joy": true, "frank": true, "rich": true, "guy": true, "drew": true,
	"chase": true, "reed": true, "robin": true, "jay": true, "dawn": true,
	"faith": true, "hap": true, "sunny": true,
	// last-name-like common words
	"read": true, "brown": true, "hill": true, "young": true, "stone": true,
	"park": true, "moon": true, "king": true, "long": true, "west": true,
	"white": true, "wood": true, "day": true, "love": true, "price": true,
	"bell": true, "cook": true, "fields": true, "banks": true, "rivers": true,
	"flowers": true, "winter": true, "summers": true, "rain": true,
}

// functionWordsMap holds English function words — determiners, pronouns,
// prepositions, conjunctions and a few correspondence formalities — that can never
// be the GIVEN NAME half of a person name.
//
// The patterns match Title-Case shape, not vocabulary, so "The Grace" satisfies
// basic_western_name exactly as "Anne Grace" does: two capitalised tokens of 2+
// letters. The surname gate then finds a real surname ("grace" IS a name) and the
// finding is reported. The article was never examined, because nothing examined it.
//
// The class is wide, not a handful of words. Measured against a single known
// surname, 49 of 49 leading function words produced a PERSON_NAME finding:
//
//	"The Morgan signed it."   -> The Morgan (67)
//	"Their Morgan signed it." -> Their Morgan (67)
//	"Via Morgan signed it."   -> Via Morgan (67)
//
// On a 1,388-file real-world corpus this class is 156 of 5,888 PERSON_NAME
// findings (2.6%), spanning 43 distinct leading words, overwhelmingly MEDIUM — so
// on the default review surface, and blocking a pre-commit hook.
//
// Only the GIVEN half is filtered, and only when the word is NOT itself a known
// name. The list is deliberately COMPLETE — it includes the modal "will"/"may",
// the article "an", the pronoun "he" and the quantifier "many" — and the name
// databases arbitrate the collisions, because every one of those is also a real
// person's name: Will Smith, May Chen, An Nguyen, He Zhang, Many (a surname).
// isFunctionWordGiven consults the databases FIRST and defers to them, so the word
// list only rejects what the data has no opinion about.
//
// Curating the collisions out of this list instead would be the wrong shape: it
// makes the list's membership depend on the name data, so every future name added
// to the databases would silently need a matching deletion here. Deferring at
// lookup time keeps the two sources independent.
//
// A single-token surname is untouched — "Morgan" alone was never a finding under
// these patterns, which require two tokens.
var functionWordsMap = map[string]bool{
	// determiners and quantifiers
	"a": true, "an": true, "the": true,
	"this": true, "that": true, "these": true, "those": true,
	"some": true, "any": true, "each": true, "every": true, "all": true,
	"both": true, "most": true, "such": true, "much": true, "many": true,
	"few": true, "several": true, "other": true, "another": true, "same": true,
	// pronouns and possessives
	"our": true, "your": true, "their": true, "his": true, "her": true,
	"its": true, "my": true, "we": true, "you": true, "they": true,
	"he": true, "she": true, "it": true, "me": true, "us": true,
	"them": true, "him": true, "who": true, "whom": true, "whose": true,
	// interrogatives and relatives
	"what": true, "which": true, "when": true, "where": true, "while": true,
	"why": true, "how": true,
	// prepositions and conjunctions
	"after": true, "before": true, "with": true, "without": true, "from": true,
	"into": true, "onto": true, "upon": true, "about": true, "above": true,
	"below": true, "under": true, "over": true, "between": true, "among": true,
	"through": true, "during": true, "against": true, "toward": true,
	"within": true, "across": true, "behind": true, "beyond": true,
	"and": true, "but": true, "or": true, "nor": true, "for": true,
	"yet": true, "so": true, "because": true, "although": true, "though": true,
	"unless": true, "until": true, "since": true, "than": true, "then": true,
	"per": true, "via": true, "of": true, "to": true, "in": true, "on": true,
	"at": true, "by": true, "as": true, "if": true, "up": true, "out": true,
	"off": true, "no": true, "not": true, "now": true, "here": true,
	"there": true, "also": true, "only": true, "just": true, "very": true,
	"more": true, "less": true, "next": true, "last": true, "too": true,
	"once": true, "ever": true, "never": true, "always": true, "often": true,
	// copulas, auxiliaries and common verbs (never a given name)
	"is": true, "are": true, "was": true, "were": true, "be": true,
	"been": true, "being": true, "have": true, "has": true, "had": true,
	"do": true, "does": true, "did": true, "would": true, "could": true,
	"should": true, "might": true, "must": true, "shall": true, "can": true,
	"will": true, "may": true, "cannot": true,
	"said": true, "says": true, "see": true, "note": true, "please": true,
	// correspondence formalities that precede a name and are not part of it.
	//
	// "attention", "subject", "bcc" and "fwd" complete the set the abbreviations
	// already covered: "attn" was here but its expansion was not, so the same memo
	// header behaved two different wrong ways — "Attn Marcus Holloway" reported
	// nothing at all, while "Attention Marcus Holloway" reported the routing word
	// INSIDE the name at 81 (#434).
	//
	// Ordinary vocabulary that can also precede a name — "signed", "contact",
	// "prepared", "reviewed" — is deliberately NOT here. Those are not correspondence
	// formalities, and admitting them would widen a suppressor on a guess; their
	// span-absorption is the pre-existing three_part_name shape already pinned by the
	// fp__business_noun_phrases corpus case, not something this list should reach.
	"dear": true, "sincerely": true, "regards": true, "thanks": true,
	"thank": true, "yes": true, "attn": true, "cc": true, "re": true,
	"attention": true, "subject": true, "bcc": true, "fwd": true,
}

// fontFamiliesMap holds multi-word font family names, which the patterns match as
// two-and-three-token Title-Case names and the surname gate then accepts whenever the
// LAST token happens to be a real surname (#406):
//
//	Times New Roman -> 81   Arial Black -> 80   Bitstream Vera -> 80
//
// Only three families actually fire, and that is the whole mechanism rather than a
// coincidence: of 37 standard multi-word families measured, the other 34 are already
// rejected because their final token ("Gothic", "Sans", "Linotype", "UI", "Pro") is not
// in the surname list. Roman, Black and Vera are. The rest of the list is here so that
// a future addition to the surname data cannot silently reopen the hole.
//
// Keyed on the WHOLE phrase, which is what makes it a safe suppressor: it can never
// silence a person named Roman or Black, because the entire matched value has to equal
// the family name. A token-level list would be the exact mistake this validator's
// history warns about.
//
// Styled variants need no entries of their own. "Times New Roman Bold" is reported as
// "Times New Roman" — the four-token span is rejected because "Bold" is not a surname —
// so the value that reaches this map is already the base family.
//
// Deliberately NOT fixed in the extractor instead: these arrive from the legacy .doc
// font table, and legacy-ole-extractor.go recovers body text by scanning for printable
// runs, which cannot tell a font-table string from a sentence. A denylist there would be
// the same list in a worse place, where it could delete real body text.
var fontFamiliesMap = map[string]bool{
	// the three measured false positives
	"times new roman": true,
	"arial black":     true,
	"bitstream vera":  true,
	// the rest of the standard multi-word families, silent today on the surname gate
	"arial narrow": true, "arial unicode ms": true, "century gothic": true,
	"book antiqua": true, "comic sans": true, "comic sans ms": true,
	"courier new": true, "franklin gothic": true, "gill sans": true,
	"lucida grande": true, "lucida console": true, "lucida sans": true,
	"palatino linotype": true, "segoe ui": true, "segoe print": true,
	"trebuchet ms": true, "bookman old style": true, "monotype corsiva": true,
	"helvetica neue": true, "avenir next": true, "myriad pro": true,
	"minion pro": true, "open sans": true, "source sans pro": true,
	"noto sans": true, "noto serif": true, "dejavu sans": true,
	"dejavu serif": true, "liberation sans": true, "liberation serif": true,
	"pt sans": true, "pt serif": true, "yu gothic": true, "yu mincho": true,
	"ms gothic": true, "ms mincho": true, "ms sans serif": true, "ms serif": true,
	"malgun gothic": true, "microsoft sans serif": true, "microsoft yahei": true,
	"hiragino sans": true, "songti sc": true, "apple chancery": true,
	"andale mono": true, "brush script mt": true, "goudy old style": true,
}

// routingWordsMap is the subset of functionWordsMap that introduces a NAME — the
// salutation and memo-header words. It drives maskNonNameGivenWords, which is a
// narrower job than the gate above and must use a narrower list.
//
// Measured why, on 714 real Office/PDF documents: masking every Title-Case function
// word recovered the salutation names it was written for but also exposed 18 findings
// that had been hidden behind an ordinary Title-Case function word, almost all of them
// false — "Firm Fixed Price" (7 hits, behind "For"), "Advice Regarding Grant" at 100,
// "Fixed Price", "Epic House". Masking is only needed where a word plausibly PRECEDES
// a person's name, and "For"/"The"/"About" introduce a noun phrase far more often than
// they introduce a person.
//
// Kept as its own map rather than a flag on the entries above so the gate's list can
// stay deliberately complete (see the note there) while this one stays deliberately
// small.
var routingWordsMap = map[string]bool{
	"attn": true, "attention": true, "cc": true, "bcc": true, "fwd": true,
	"re": true, "subject": true,
	"dear": true, "sincerely": true, "regards": true, "thanks": true, "thank": true,
}

// emailPatternsMap for efficient email context analysis
var emailPatternsMap = map[string]bool{
	"from:":        true,
	"to:":          true,
	"cc:":          true,
	"sent by":      true,
	"regards":      true,
	"sincerely":    true,
	"best regards": true,
	"kind regards": true,
}

var businessPatternsMap = map[string]bool{
	"inc":             true,
	"llc":             true,
	"ltd":             true,
	"corp":            true,
	"corporation":     true,
	"company":         true,
	"enterprises":     true,
	"industries":      true,
	"manufacturing":   true,
	"consulting":      true,
	"group":           true,
	"associates":      true,
	"catalog":         true,
	"product":         true,
	"brand":           true,
	"version":         true,
	"series":          true,
	"interface":       true,
	"auditor":         true,
	"manager":         true,
	"troubleshooting": true,
	"guide":           true,
	"documentation":   true,
	"readme":          true,
	"installation":    true,
	"setup":           true,
	"config":          true,
	"script":          true,
	"automation":      true,
	"parameters":      true,
	"concurrency":     true,
	"errors":          true,
	"intervention":    true,
	"required":        true,
	"table":           true,
	"database":        true,
	"cross-account":   true,
	"stackset":        true,
	"resource":        true,
	"groups":          true,
	"patch":           true,
	"ansible":         true,
	"aws":             true,
	"ssm":             true,
	"ec2":             true,
	"s3":              true,
	"lambda":          true,
	"cloudformation":  true,
	"terraform":       true,
}

var productPatternsMap = map[string]bool{
	"air":      true,
	"tennis":   true,
	"baby":     true,
	"golf":     true,
	"made":     true,
	"racket":   true,
	"shampoo":  true,
	"clubs":    true,
	"nike":     true,
	"samsung":  true,
	"ford":     true,
	"galaxy":   true,
	"explorer": true,
	"firearm":  true,
	"weapon":   true,
}

var geoPatternsMap = map[string]bool{
	"city":     true,
	"county":   true,
	"state":    true,
	"mountain": true,
	"lake":     true,
	"river":    true,
	"creek":    true,
	"valley":   true,
	// "park" intentionally omitted: it is a very common surname (Korean 박, and
	// English), so a standalone -35 geo penalty suppressed every real "... Park"
	// name outright ("Sarah Park approved" scored 0). Genuine addresses are still
	// caught by the following geo token ("Park Street"/"Park Avenue" via
	// street/avenue), and "national park" prose lacks a name-shaped bigram.
	"street":    true,
	"avenue":    true,
	"road":      true,
	"drive":     true,
	"boulevard": true,
}
