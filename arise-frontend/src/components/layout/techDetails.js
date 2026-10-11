// Public, high-level descriptions of the technologies shown in the footer.
// Intentionally generic: describes each technology and the kind of value it
// adds, NOT how ARISE configures, weights or combines them internally.
// Keep it that way when editing.

export const TECH_GROUPS = [
  { heading: 'Analysis Engines',   keys: ['radare2', 'ghidra', 'capa'] },
  { heading: 'Security Standards', keys: ['attack', 'cvss'] },
];

export const TECH_DETAILS = {
  radare2: {
    name: 'Radare2',
    kind: 'Analysis Engine',
    summary: 'Open-source reverse-engineering framework.',
    what: 'Radare2 (often shortened to r2) is an open-source framework for inspecting and analysing binary files. It supports a wide range of file formats and processor architectures.',
    role: 'A command-line-driven toolkit for disassembly, binary inspection and static analysis, widely used in reverse engineering and malware research.',
    usefulFor: [
      'Reading the structure of executables without running them',
      'Disassembling code and locating functions',
      'Surfacing imports, strings and other artefacts embedded in a file',
    ],
    benefit: 'Static inspection lets analysts examine a suspicious file safely, without executing it, and quickly see what it is made of.',
    arise: 'ARISE uses Radare2 as one source of static evidence from uploaded files, such as structural information, imported functionality, strings and function-level details, which then feeds the rest of the analysis.',
    link: { label: 'radare.org', href: 'https://www.radare.org' },
  },
  ghidra: {
    name: 'Ghidra',
    kind: 'Analysis Engine',
    summary: 'Open-source software reverse-engineering suite.',
    what: 'Ghidra is a software reverse-engineering framework originally developed by the U.S. National Security Agency and released as open source in 2019.',
    role: 'Provides disassembly and decompilation, turning machine code into a more readable, higher-level representation that is easier to reason about.',
    usefulFor: [
      'Understanding what compiled code is doing',
      'Reviewing program logic in a readable form',
      'Supporting in-depth reverse-engineering of unfamiliar binaries',
    ],
    benefit: 'Decompilation reduces the effort needed to interpret low-level code, helping analysts form an understanding of a sample sooner.',
    arise: 'ARISE uses Ghidra as an additional source of reverse-engineering evidence, complementing other static analysis sources.',
    link: { label: 'ghidra-sre.org', href: 'https://ghidra-sre.org' },
  },
  capa: {
    name: 'CAPA',
    kind: 'Analysis Engine',
    summary: 'Identifies capabilities in executable files.',
    what: 'CAPA is an open-source tool from Mandiant’s FLARE team that detects capabilities in executable files using a publicly maintained set of rules.',
    role: 'Capability-oriented analysis: instead of listing raw code, it describes what a program appears able to do, such as communicating over a network or manipulating files.',
    usefulFor: [
      'Summarising a binary’s potential behaviour in plain terms',
      'Triaging unknown samples faster',
      'Relating findings to public behaviour and ATT&CK references',
    ],
    benefit: 'Capability summaries help analysts prioritise samples and focus on the behaviours that matter, rather than reading every function.',
    arise: 'ARISE uses CAPA to add capability-level context to its findings, so results describe what a file may be capable of, not just what it contains.',
    link: { label: 'github.com/mandiant/capa', href: 'https://github.com/mandiant/capa' },
  },
  attack: {
    name: 'MITRE ATT&CK',
    kind: 'Security Standard',
    summary: 'Public knowledge base of adversary tactics and techniques.',
    what: 'MITRE ATT&CK is a freely available, globally used knowledge base of adversary tactics and techniques, based on real-world observations and maintained by MITRE.',
    role: 'A common vocabulary for describing attacker behaviour. Tactics describe the attacker’s goal; techniques describe how it is pursued, each with a reference ID such as T1055.',
    usefulFor: [
      'Describing behaviour in a shared, industry-recognised language',
      'Communicating findings between analysts, SOC and leadership',
      'Relating observations to defensive and detection planning',
    ],
    benefit: 'Mapping observations to ATT&CK gives findings context and makes them easier to compare, report and act on.',
    arise: 'ARISE uses ATT&CK concepts to contextualise observed behaviours and capabilities, and shows the related technique references in its results.',
    link: { label: 'attack.mitre.org', href: 'https://attack.mitre.org' },
  },
  cvss: {
    name: 'CVSS v3.1',
    kind: 'Security Standard',
    summary: 'Public standard for expressing severity.',
    what: 'The Common Vulnerability Scoring System (CVSS) is an open standard, maintained by FIRST, for describing the severity of security issues. Version 3.1 is a published revision of that specification.',
    role: 'Expresses severity on a 0.0 to 10.0 scale with named ratings (None, Low, Medium, High and Critical), so severity can be compared consistently.',
    usefulFor: [
      'Giving findings a familiar, standardised severity scale',
      'Helping teams prioritise what to look at first',
      'Communicating severity to non-specialist stakeholders',
    ],
    benefit: 'A standard scale gives teams a shared reference point when deciding how urgently to respond.',
    arise: 'ARISE presents severity on the familiar CVSS scale as additional context alongside its other findings.',
    note: 'CVSS was designed for vulnerabilities. In ARISE it is a contextual indicator, not a formal vulnerability assessment.',
    link: { label: 'first.org/cvss', href: 'https://www.first.org/cvss/v3.1/specification-document' },
  },
};
