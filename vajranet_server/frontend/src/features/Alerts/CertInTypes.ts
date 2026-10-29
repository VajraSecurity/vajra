export interface CertinFormDataType {
  iAm: 'the affected entity' | 'reporting incident affecting other entity' | '';
  reporterRole: 'Individual' | 'Organization' | '';
  reporterNameTitle: string;
  reporterOrganization: string;
  reporterContactNo: string;
  reporterEmail: string;
  reporterAddress: string;
  affectedEntity: string;
  incidentTypes: string[];
  otherIncidentType: string;
  isCritical: 'Yes' | 'No' | '';
  criticalBriefDetails: string;
  affectedSystemDomainUrl: string;
  affectedSystemIp: string;
  affectedSystemOs: string;
  affectedSystemMakeModelCloud: string;
  affectedSystemAppDetails: string;
  affectedSystemLocation: string;
  affectedSystemIsp: string;
  incidentBriefDescription: string;
  occurrenceDateTime: string;
  detectionDateTime: string;
}

export const INCIDENT_TYPES_COL_1 = [
  "Targeted scanning/probing of critical networks/systems",
  "Compromise of critical systems/information",
  "Unauthorised access of IT systems/data",
  "Defacement or intrusion into the website",
  "Malicious code attacks",
  "Attack on servers such as Database, Mail and DNS and network devices such as Routers",
  "Identity Theft, spoofing and phishing attacks",
  "DoS/DDoS attacks",
  "Attacks on Critical infrastructure, SCADA and operational technology systems and Wireless networks",
  "Attacks on Application such as E-Governance, E-Commerce etc."
];

export const INCIDENT_TYPES_COL_2 = [
  "Data Breach",
  "Data Leak",
  "Attacks on Internet of Things (IoT) devices and associated systems, networks, software, servers",
  "Attacks or incident affecting Digital Payment systems",
  "Attacks through Malicious mobile Apps",
  "Fake mobile Apps",
  "Unauthorised access to social media accounts",
  "Attacks or malicious/ suspicious activities affecting Cloud computing systems/servers/software/applications"
];

export const INCIDENT_TYPES_COL_3 = [
  "Attacks or malicious/suspicious activities affecting systems/ servers/ networks/ software/ applications related to Big Data, Block chain, virtual assets, virtual asset exchanges, custodian wallets, Robotics, 3D and 4D Printing, additive manufacturing, Drones",
  "Attacks or malicious/ suspicious activities affecting systems/ servers/software/ applications related to Artificial Intelligence and Machine Learning",
  "Other (Please Specify)"
];

export const initialCertinFormData: CertinFormDataType = {
  iAm: '',
  reporterRole: '',
  reporterNameTitle: '',
  reporterOrganization: '',
  reporterContactNo: '',
  reporterEmail: '',
  reporterAddress: '',
  affectedEntity: '',
  incidentTypes: [],
  otherIncidentType: '',
  isCritical: '',
  criticalBriefDetails: '',
  affectedSystemDomainUrl: '',
  affectedSystemIp: '',
  affectedSystemOs: '',
  affectedSystemMakeModelCloud: '',
  affectedSystemAppDetails: '',
  affectedSystemLocation: '',
  affectedSystemIsp: '',
  incidentBriefDescription: '',
  occurrenceDateTime: '',
  detectionDateTime: '',
};
