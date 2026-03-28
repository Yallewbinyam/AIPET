# AIPET: An Explainable AI-Powered Penetration Testing 
# Framework for IoT Vulnerability Discovery

**Student:** Binyam  
**Programme:** MSc Cyber Security (Ethical Hacking)  
**Institution:** Coventry University  
**Supervisor:** [Supervisor Name]  
**Date:** September 2025  

---

# Chapter 1: Introduction

## 1.1 Background and Motivation

The Internet of Things (IoT) represents one of the most
significant technological shifts of the twenty-first century.
By 2024, an estimated 18.8 billion IoT devices were actively
deployed globally, spanning domestic environments, healthcare
infrastructure, industrial control systems, and critical
national infrastructure (Statista, 2024). This proliferation
of connected devices has fundamentally transformed how
organisations operate, enabling unprecedented levels of
automation, efficiency, and data collection. However, this
connectivity has simultaneously created an attack surface of
extraordinary scale and complexity.

Unlike traditional enterprise computing environments, IoT
devices present a unique security challenge. Constrained by
limited processing power, memory, and battery capacity, these
devices frequently operate with minimal security hardening.
Manufacturers have historically prioritised functionality and
cost over security, resulting in devices that ship with default
credentials, unencrypted communication channels, outdated
firmware, and no mechanism for security updates (Mosenia and
Jha, 2017). The consequences of this systemic insecurity are
well documented. The Mirai botnet of 2016 exploited hardcoded
credentials in IoT firmware to compromise over 600,000 devices,
launching the largest distributed denial-of-service attack
recorded at that time and causing widespread internet disruption
across North America and Europe (Antonakakis et al., 2017).
More recent incidents have demonstrated that IoT vulnerabilities
extend beyond availability attacks to encompass data breaches,
ransomware, and nation-state intrusions into critical
infrastructure.

Despite the scale and severity of the IoT security challenge,
the tools available for assessing IoT system security remain
fragmented, inconsistent, and largely inaccessible to the
organisations that need them most. Existing penetration testing
frameworks were designed for traditional enterprise IT
environments and lack native support for the protocols,
architectures, and attack surfaces that characterise IoT
deployments. Security professionals attempting to assess IoT
systems must assemble a collection of disparate tools — none
of which were designed to work together — and apply them
manually, relying on individual expertise and intuition to
prioritise findings. For small and medium-sized businesses,
which constitute the majority of IoT adopters, this approach
is prohibitively expensive, time-consuming, and inconsistent.

This dissertation presents AIPET (AI-Powered Penetration
Testing Framework), a novel open-source framework that
addresses this gap through the integration of IoT-specific
attack modules with an explainable artificial intelligence
engine. AIPET automates the reconnaissance, protocol-level
testing, firmware analysis, and vulnerability prioritisation
phases of an IoT penetration testing engagement, producing
actionable findings with transparent, human-readable
explanations generated through SHAP (SHapley Additive
exPlanations) values. The framework is designed to be
accessible to security professionals across all scales of
deployment, from individual consultants assessing a single
IoT device to enterprise security teams managing thousands
of connected assets.

## 1.2 Research Problem

The central problem this research addresses is the absence
of an integrated, intelligent, and accessible penetration
testing framework specifically designed for IoT environments.
Three distinct gaps motivate this work:

The first gap is **tooling fragmentation**. No existing
open-source tool combines IoT-specific protocol attack
modules — covering MQTT, CoAP, HTTP-based IoT interfaces,
and firmware analysis — into a unified, automated workflow.
Security professionals currently rely on general-purpose
tools such as Nmap, Metasploit, and Wireshark, supplemented
by protocol-specific utilities that lack integration and
require substantial manual effort to operate effectively.

The second gap is **the absence of AI-driven prioritisation**.
A comprehensive IoT security assessment generates hundreds
of findings across multiple attack surfaces. Without
intelligent prioritisation, security teams must rely on
analyst experience and intuition to determine which
vulnerabilities require immediate remediation. This
introduces inconsistency, increases the risk of critical
findings being overlooked, and limits the scalability of
IoT security assessment programmes.

The third gap is **the lack of explainability**. Emerging
AI-assisted security tools that do incorporate machine
learning produce black-box outputs — severity ratings or
risk scores without justification. Enterprise security teams,
operating under compliance and audit requirements, cannot
act on unexplained AI recommendations. The absence of
explainability undermines trust, prevents accountability,
and limits the practical utility of AI in offensive security
contexts.

AIPET directly addresses all three gaps through its modular
architecture, trained machine learning classifier, and SHAP-
based explanation engine.

## 1.3 Research Aims and Objectives

The primary aim of this research is to design, implement,
and validate an explainable AI-powered penetration testing
framework specifically designed for IoT environments, and
to evaluate whether AI-driven vulnerability prioritisation
improves security assessment outcomes compared to manual
approaches.

This aim is pursued through the following specific objectives:

1. To conduct a comprehensive review of existing IoT security
   frameworks, penetration testing methodologies, and the
   application of artificial intelligence in offensive
   security, identifying the research gaps that AIPET
   addresses.

2. To design and implement a modular IoT penetration testing
   framework comprising seven integrated modules covering
   reconnaissance, MQTT protocol attack, CoAP protocol
   attack, HTTP web interface attack, firmware analysis,
   explainable AI vulnerability prioritisation, and
   automated report generation.

3. To train and evaluate a Random Forest machine learning
   classifier on a synthesised IoT vulnerability dataset,
   achieving a weighted F1-score of at least 0.85 on
   held-out test data.

4. To implement SHAP-based explainability for all AI
   predictions, producing human-readable justifications
   that identify which device characteristics drove each
   vulnerability severity assessment.

5. To validate AIPET against OWASP IoTGoat v1.0, an
   independently developed deliberately vulnerable IoT
   firmware image, and to compare AIPET's assessment
   performance against a manual baseline assessment on
   the same target.

6. To release AIPET as an open-source tool under the MIT
   licence, contributing a reusable, documented, and
   validated framework to the global IoT security community.

## 1.4 Research Questions

This dissertation is structured around three overarching
research questions:

**RQ1:** Can a modular, automated penetration testing
framework effectively identify and assess vulnerabilities
across the primary IoT attack surfaces — network protocols,
web interfaces, and firmware — within a controlled virtual
environment?

**RQ2:** Can a machine learning classifier trained on IoT
vulnerability data achieve a weighted F1-score of 0.85 or
above, and can SHAP values provide meaningful, actionable
explanations of its predictions?

**RQ3:** Does AI-driven vulnerability prioritisation improve
IoT security assessment in terms of coverage, speed, and
consistency compared to a manual assessment baseline?

## 1.5 Scope and Limitations

AIPET is scoped to address the most prevalent IoT attack
surfaces documented in the OWASP IoT Top 10 (2018) framework.
The framework covers ten of the ten OWASP IoT attack
categories across its seven modules. The following
limitations apply to the current implementation:

All validation testing was conducted within an isolated
virtual laboratory environment. Physical hardware testing,
which would enable assessment of radio frequency protocols
(Bluetooth, Zigbee, Z-Wave) and hardware-level attack
surfaces (JTAG, UART, side-channel analysis), is beyond
the scope of this work and is identified as a direction
for future research.

The AI model was trained on a synthesised dataset of 2,000
samples derived from IoT CVE patterns rather than a
comprehensive real-world CVE dataset. While the synthetic
dataset was constructed to reflect documented vulnerability
distributions, model performance on real-world deployments
may differ from laboratory evaluation results. This
limitation is documented and quantified in Chapter 5.

AIPET is designed exclusively for use in authorised
penetration testing engagements. All testing conducted
during this research was performed within an isolated
environment in full compliance with Coventry University
ethical research guidelines and the Computer Misuse
Act 1990.

## 1.6 Dissertation Structure

The remainder of this dissertation is organised as follows.
Chapter 2 presents a critical review of the literature
spanning IoT security, penetration testing methodologies,
and the application of artificial intelligence and
explainability in cybersecurity. Chapter 3 describes the
research methodology, detailing the Design Science Research
approach, virtual laboratory design, and evaluation
framework. Chapter 4 presents the design and implementation
of the AIPET framework, documenting each of the seven
modules and the key technical decisions that shaped the
architecture. Chapter 5 presents the evaluation results,
including virtual laboratory testing, IoTGoat validation,
baseline comparison, and AI model performance metrics.
Chapter 6 discusses the implications of the findings,
addresses the research questions, and critically evaluates
the limitations of the work. Chapter 7 concludes the
dissertation with a summary of contributions, answers to
the research questions, and directions for future research
including a proposed PhD extension pathway.

---

---

# Chapter 2: Literature Review

## 2.1 The IoT Security Landscape

The proliferation of Internet of Things devices has created
an attack surface of unprecedented scale. Atzori, Iera and
Morabito (2010) define the Internet of Things as a pervasive
network of physical objects embedded with sensors,
actuators, and communication capabilities, capable of
exchanging data with minimal human intervention. By 2024
an estimated 18.8 billion such devices were actively
deployed globally, with projections suggesting this figure
will exceed 30 billion by 2030 (Statista, 2024). This
exponential growth has occurred largely without a
corresponding advancement in security practice.

The security challenges inherent to IoT environments
differ fundamentally from those encountered in traditional
enterprise computing. Constraints of processing power,
memory, and energy consumption prevent the application
of conventional security mechanisms such as full TLS
implementations, certificate-based authentication, and
real-time intrusion detection (Mosenia and Jha, 2017).
Manufacturers operating in competitive markets have
historically prioritised cost reduction and time-to-market
over security engineering, resulting in devices that ship
with default credentials, unencrypted communication
channels, and firmware that receives no security updates
after initial deployment (Miettinen et al., 2017).

The consequences of this systemic insecurity have been
well documented through a series of high-profile incidents.
The Mirai botnet of 2016, analysed comprehensively by
Antonakakis et al. (2017), demonstrated the catastrophic
potential of IoT security failures at scale. By exploiting
hardcoded default credentials across a range of consumer
IoT devices — IP cameras, digital video recorders, and
home routers — Mirai compromised over 600,000 devices and
orchestrated a distributed denial-of-service attack that
disrupted internet infrastructure across North America and
Europe. The attack generated peak traffic exceeding 1.1
terabits per second, a volume unprecedented at the time.
Crucially, the vulnerability exploited by Mirai — hardcoded
credentials that users could not change — represents a
class of firmware-level vulnerability that remains
prevalent in IoT deployments today (Kolias et al., 2017).

More recent incidents have demonstrated that IoT
vulnerabilities extend beyond availability attacks.
The exploitation of vulnerabilities in building management
systems, medical devices, and industrial control systems
has demonstrated the potential for IoT security failures
to have direct physical consequences (Lee and Lee, 2015).
The OWASP IoT Top 10 (OWASP, 2018) provides a structured
taxonomy of the most prevalent IoT vulnerability categories,
encompassing weak or hardcoded passwords, insecure network
services, insecure ecosystem interfaces, lack of secure
update mechanisms, use of insecure or outdated components,
insufficient privacy protection, insecure data transfer and
storage, lack of device management, insecure default
settings, and lack of physical hardening. This framework
provides the foundational structure against which AIPET's
coverage is evaluated in Chapter 5.

## 2.2 Existing IoT Penetration Testing Tools and Frameworks

A survey of existing IoT security assessment tools reveals
a landscape characterised by fragmentation, specialisation,
and the absence of integrated AI-driven prioritisation.
Existing tools fall broadly into three categories: network
scanning tools adapted for IoT environments, protocol-
specific attack tools, and firmware analysis utilities.

Network scanning tools represent the most mature category.
Nmap (Lyon, 2009) provides comprehensive port scanning and
service detection capabilities and serves as the foundation
for AIPET's reconnaissance module. However, Nmap provides
no IoT-specific device fingerprinting, no protocol-level
attack capabilities, and no vulnerability prioritisation.
Shodan, described by Matherly (2015) as a search engine
for internet-connected devices, provides passive discovery
of exposed IoT services but offers no active testing
capabilities. Neither tool provides AI-driven analysis
or automated reporting.

Protocol-specific tools address individual IoT attack
surfaces in isolation. MQTT Explorer and MQTT-PWN provide
MQTT broker testing capabilities comparable to AIPET's
Module 2, but require manual operation and produce no
structured output suitable for professional reporting.
Cancoap and CoAPthon provide CoAP protocol interaction
capabilities but lack security-oriented attack automation.
These tools are valuable for expert practitioners but
inaccessible to the broader population of IoT device owners
and IT administrators who lack specialist knowledge.

Firmware analysis represents the most technically
sophisticated category. Binwalk (Heffner, 2010) provides
firmware extraction and signature-based analysis and is
incorporated within AIPET's Module 5. Firmadyne (Chen
et al., 2016) provides automated dynamic analysis of
Linux-based embedded firmware through emulation but
requires significant technical expertise and infrastructure
to operate. The Firmware Analysis and Comparison Tool
(FACT) provides static analysis capabilities but produces
raw findings without severity assessment or prioritisation.
Costin et al. (2014) conducted the most comprehensive
large-scale analysis of embedded firmware security to date,
analysing over 30,000 firmware images and identifying
systemic vulnerabilities including hardcoded credentials,
outdated components, and private key exposure — precisely
the vulnerability classes targeted by AIPET's firmware
module.

The critical gap across all existing tools is the absence
of integration. A comprehensive IoT security assessment
using available tools requires a practitioner to operate
five or more separate utilities, manually correlate their
outputs, and apply expert judgment to prioritise findings.
This process is time-consuming, inconsistent, and
inaccessible to non-specialists. AIPET addresses this gap
through a unified pipeline that automates the entire
assessment workflow from discovery to professional report.

## 2.3 Artificial Intelligence in Cybersecurity

The application of machine learning to cybersecurity
problems has attracted substantial research attention
over the past decade. Buczak and Guven (2016) provide
a comprehensive survey of machine learning methods applied
to network intrusion detection, identifying Random Forest,
Support Vector Machine, and neural network approaches as
the most effective classifiers for network security
applications. Sommer and Paxson (2010) provide a critical
analysis of the challenges of applying machine learning
to intrusion detection, identifying the problem of rare
attack classes — directly relevant to AIPET's class
imbalance challenge documented in Chapter 5.

Supervised classification approaches have demonstrated
strong performance in vulnerability assessment contexts.
Bozorgi et al. (2010) applied support vector machines
to predict vulnerability exploitability from NVD CVE
data, achieving significant improvements over CVSS
score-based prioritisation alone. This work establishes
the precedent for AI-driven vulnerability prioritisation
that AIPET extends to the IoT context. Sabetta and
Bezzi (2018) demonstrated that machine learning models
trained on code change patterns could predict security-
relevant software changes with high accuracy, illustrating
the breadth of security problems amenable to ML approaches.

Random Forest classifiers, which form the core of
AIPET's AI engine, have demonstrated particular suitability
for security classification tasks. Breiman (2001) introduced
the Random Forest algorithm and demonstrated its robustness
to overfitting through ensemble averaging across multiple
decision trees. The algorithm's native support for feature
importance scoring makes it especially valuable in security
contexts where understanding which features drive a
prediction is as important as the prediction itself.
Liaw and Wiener (2002) provide the foundational analysis
of Random Forest performance characteristics that informs
AIPET's model architecture decisions documented in
Chapter 3.

The application of machine learning specifically to IoT
security assessment has received less attention than
network-level intrusion detection. Meidan et al. (2018)
applied autoencoders to IoT device fingerprinting and
anomaly detection, demonstrating that IoT devices exhibit
sufficiently distinctive network behaviour patterns for
ML-based classification. Doshi et al. (2018) applied
machine learning to IoT botnet detection at the network
level, achieving high detection rates against Mirai and
BASHLITE variants. These works establish the viability
of ML-based IoT security analysis but do not address
the penetration testing context or vulnerability
prioritisation problem that AIPET targets.

## 2.4 Explainable Artificial Intelligence

The emergence of explainable AI as a distinct research
area reflects a fundamental limitation of conventional
machine learning: the inability to justify predictions
in human-understandable terms. Doshi-Velez and Kim (2017)
provide a foundational framework for interpretability
in machine learning, distinguishing between intrinsic
interpretability — models that are inherently understandable
such as decision trees — and post-hoc interpretability —
techniques that explain the predictions of complex models
after the fact. AIPET employs post-hoc explainability
through SHAP values, enabling the use of a high-performance
Random Forest classifier while providing transparent
justification for each prediction.

Lundberg and Lee (2017) introduced SHAP (SHapley Additive
exPlanations), which grounds feature attribution in
cooperative game theory through Shapley values first
formalised by Shapley (1953). The key theoretical
property of SHAP values — consistency and local accuracy
— distinguishes them from earlier attribution methods
such as LIME (Ribeiro, Singh and Guestrin, 2016). Where
LIME approximates explanations through local linear
models that may be inconsistent across similar inputs,
SHAP values provide theoretically guaranteed attribution
that sums to the difference between the model output
and the expected output. For AIPET's security application,
this consistency property is essential: a security
analyst must be able to trust that the explanation
accurately reflects the model's reasoning rather than
an approximation that may mislead remediation decisions.

The regulatory imperative for explainable AI has
strengthened considerably since the introduction of
the EU General Data Protection Regulation (GDPR) in
2018, which established a right to explanation for
automated decisions affecting individuals (Goodman and
Flaxman, 2017). The EU Artificial Intelligence Act
(European Commission, 2021), which classifies AI systems
used in critical infrastructure security as high-risk,
mandates transparency and human oversight requirements
that necessitate explainability. AIPET's SHAP
implementation positions it as compliant with the
direction of AI regulation in security contexts, a
significant advantage over black-box AI security tools.

In the specific context of security tools, the value
of explainability extends beyond regulatory compliance.
Chio and Freeman (2018) argue that security analysts
require not just threat detection but threat understanding
— the ability to comprehend why a system was flagged
as vulnerable in order to prioritise remediation
effectively and communicate risk to non-technical
stakeholders. Explainability transforms AIPET from a
classification tool into a decision support system,
providing security teams with the justification
necessary to act on AI recommendations with confidence.

## 2.5 The Research Gap

The literature review reveals a clear and specific research
gap that AIPET addresses: no existing open-source tool
combines IoT-specific protocol attack automation with
AI-driven vulnerability prioritisation and explainable
output. This gap has three dimensions.

The first dimension is integration. Existing IoT security
tools address individual attack surfaces in isolation.
The security practitioner assessing an IoT deployment
must operate multiple tools, manually correlate their
outputs, and synthesise findings without computational
support. AIPET provides the first unified pipeline
that progresses automatically from network reconnaissance
through protocol-level attack to firmware analysis and
AI-driven prioritisation.

The second dimension is intelligence. Existing tools
produce lists of findings without prioritisation. The
security practitioner must apply expert judgment to
determine which findings require immediate attention.
For organisations without dedicated IoT security
expertise — which constitute the majority of IoT
adopters — this creates a critical gap between findings
and action. AIPET's Random Forest classifier, trained
on IoT CVE patterns, provides evidence-based
prioritisation that does not require specialist expertise
to interpret.

The third dimension is explainability. Emerging AI-assisted
security tools that do incorporate machine learning
produce black-box outputs — severity ratings without
justification. Enterprise security teams, operating under
compliance frameworks that require audit trails for
security decisions, cannot act on unexplained AI
recommendations. AIPET's SHAP implementation provides
per-prediction feature attribution that explains exactly
which device characteristics drove each severity
assessment, enabling accountable, auditable security
decisions.

This three-dimensional gap — integration, intelligence,
and explainability — defines the research problem that
AIPET addresses and provides the evaluative framework
against which the framework's contributions are assessed
in Chapter 5.

## 2.6 Summary

This chapter has reviewed the literature spanning IoT
security, penetration testing methodologies, machine
learning in cybersecurity, and explainable AI. The review
has established that IoT environments present security
challenges of unprecedented scale and severity, that
existing tools address individual aspects of IoT security
assessment without integration or intelligent prioritisation,
that machine learning approaches have demonstrated strong
performance in security classification tasks, and that
SHAP-based explainability provides theoretically grounded
and regulatory-compliant transparency for AI security
tools. The convergence of these findings identifies the
specific research gap that AIPET addresses and motivates
the design decisions documented in Chapter 3.

## References for Chapter 2

Antonakakis, M., April, T., Bailey, M., Bernhard, M.,
Bursztein, E., Cochran, J., Durumeric, Z., Halderman,
J.A., Invernizzi, L., Kallitsis, M. and Kumar, D. (2017)
'Understanding the Mirai botnet', in Proceedings of the
26th USENIX Security Symposium, pp. 1093-1110.

Atzori, L., Iera, A. and Morabito, G. (2010) 'The Internet
of Things: A survey', Computer Networks, 54(15),
pp. 2787-2805.

Bozorgi, M., Saul, L.K., Savage, S. and Voelker, G.M.
(2010) 'Beyond blacklisting: Learning to detect malicious
web sites from suspicious URLs', in Proceedings of the
16th ACM SIGKDD International Conference on Knowledge
Discovery and Data Mining, pp. 1245-1254.

Breiman, L. (2001) 'Random forests', Machine Learning,
45(1), pp. 5-32.

Buczak, A.L. and Guven, E. (2016) 'A survey of data
mining and machine learning methods for cyber security
intrusion detection', IEEE Communications Surveys and
Tutorials, 18(2), pp. 1153-1176.

Chen, D.D., Woo, M., Brumley, D. and Egele, M. (2016)
'Towards automated dynamic analysis for Linux-based
embedded firmware', in Proceedings of the Network and
Distributed System Security Symposium (NDSS).

Chio, C. and Freeman, D. (2018) Machine Learning and
Security. Sebastopol: O'Reilly Media.

Costin, A., Zaddach, J., Francillon, A. and Balzarotti, D.
(2014) 'A large-scale analysis of the security of embedded
firmwares', in Proceedings of the 23rd USENIX Security
Symposium, pp. 95-110.

Doshi, R., Apthorpe, N. and Feamster, N. (2018) 'Machine
learning DDoS detection for consumer Internet of Things
devices', in Proceedings of the IEEE Security and Privacy
Workshops, pp. 29-35.

Doshi-Velez, F. and Kim, B. (2017) 'Towards a rigorous
science of interpretable machine learning', arXiv preprint
arXiv:1702.08608.

European Commission (2021) Proposal for a Regulation
of the European Parliament and of the Council Laying
Down Harmonised Rules on Artificial Intelligence.
Brussels: European Commission.

Goodman, B. and Flaxman, S. (2017) 'European Union
regulations on algorithmic decision-making and a right
to explanation', AI Magazine, 38(3), pp. 50-57.

Heffner, C. (2010) Binwalk: Firmware Analysis Tool.
Available at: https://github.com/ReFirmLabs/binwalk

Kolias, C., Kambourakis, G., Stavrou, A. and Voas, J.
(2017) 'DDoS in the IoT: Mirai and other botnets',
Computer, 50(7), pp. 80-84.

Lee, I. and Lee, K. (2015) 'The Internet of Things (IoT):
Applications, investments, and challenges for enterprises',
Business Horizons, 58(4), pp. 431-440.

Liaw, A. and Wiener, M. (2002) 'Classification and
regression by randomForest', R News, 2(3), pp. 18-22.

Lundberg, S.M. and Lee, S.I. (2017) 'A unified approach
to interpreting model predictions', Advances in Neural
Information Processing Systems, 30, pp. 4765-4774.

Lyon, G. (2009) Nmap Network Scanning. Sunnyvale:
Insecure.Com LLC.

Matherly, J. (2015) Complete Guide to Shodan. Shodan.

Meidan, Y., Bohadana, M., Mathov, Y., Mirsky, Y.,
Shabtai, A., Breitenbacher, D. and Elovici, Y. (2018)
'N-BaIoT: Network-based detection of IoT botnet attacks
using deep autoencoders', IEEE Pervasive Computing,
17(3), pp. 12-22.

Miettinen, M., Marchal, S., Hafeez, I., Asokan, N.,
Sadeghi, A.R. and Tarkoma, S. (2017) 'IoT sentinel:
Automated device-type identification for security
enforcement in IoT', in Proceedings of the 37th IEEE
International Conference on Distributed Computing
Systems, pp. 2177-2184.

Mosenia, A. and Jha, N.K. (2017) 'A comprehensive study
of security of Internet-of-Things', IEEE Transactions on
Emerging Topics in Computing, 5(4), pp. 586-602.

OWASP (2018) OWASP Internet of Things Top 10.
Available at: https://owasp.org/www-project-internet-of-things/

Ribeiro, M.T., Singh, S. and Guestrin, C. (2016) 'Why
should I trust you? Explaining the predictions of any
classifier', in Proceedings of the 22nd ACM SIGKDD
International Conference on Knowledge Discovery and
Data Mining, pp. 1135-1144.

Sabetta, A. and Bezzi, M. (2018) 'A practical approach
to the automatic classification of security-relevant
commits', in Proceedings of the 34th IEEE International
Conference on Software Maintenance and Evolution,
pp. 579-582.

Shapley, L.S. (1953) 'A value for n-person games',
Contributions to the Theory of Games, 2(28), pp. 307-317.

Sommer, R. and Paxson, V. (2010) 'Outside the closed
world: On using machine learning for network intrusion
detection', in Proceedings of the 31st IEEE Symposium
on Security and Privacy, pp. 305-316.

Statista (2024) Internet of Things — Number of Connected
Devices Worldwide. Available at: https://www.statista.com