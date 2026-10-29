import { Document, Page, Text, View, StyleSheet, Svg, Path } from '@react-pdf/renderer';
import { INCIDENT_TYPES_COL_1, INCIDENT_TYPES_COL_2, INCIDENT_TYPES_COL_3 } from './CertInTypes';
import type { CertinFormDataType } from './CertInTypes';

const s = StyleSheet.create({
  page: { padding: 30, fontSize: 9, fontFamily: 'Helvetica' },
  title: { fontSize: 14, fontWeight: 'bold', textAlign: 'center', marginBottom: 5 },
  table: { borderTop: 1, borderLeft: 1, borderColor: '#000' },
  row: { flexDirection: 'row', borderBottom: 1, borderColor: '#000' },
  col: { borderRight: 1, borderColor: '#000', padding: 4 },
  headerCol: { backgroundColor: '#d3d3d3', borderRight: 1, borderColor: '#000', padding: 4, fontWeight: 'bold', textAlign: 'center' },
  bold: { fontWeight: 'bold', fontFamily: 'Helvetica-Bold' },
  text: { fontSize: 9 },
  checkbox: { width: 10, height: 10, border: 1, borderColor: '#000', marginRight: 4, display: 'flex', alignItems: 'center', justifyContent: 'center' },
  flexRow: { flexDirection: 'row', alignItems: 'center' },
  mb2: { marginBottom: 4 },
  inputField: { backgroundColor: '#f1f5f9', paddingHorizontal: 3, paddingVertical: 1, minHeight: 12 }
});

const Checkbox = ({ checked }: { checked: boolean }) => (
  <View style={s.checkbox}>
    {checked && (
      <Svg viewBox="0 0 24 24" width={8} height={8}>
        <Path
          d="M20 6L9 17l-5-5"
          style={{ stroke: 'black', strokeWidth: 3, fill: 'none' }}
        />
      </Svg>
    )}
  </View>
);

export const CertInPDFDocument = ({ data }: { data: CertinFormDataType }) => (
  <Document>
    <Page size="A4" style={s.page}>
      <Text style={s.title}>Incident Reporting Form</Text>
      
      <View style={s.table}>
        {/* Row 1: I am */}
        <View style={s.row}>
          <View style={[s.col, { width: '100%', flexDirection: 'row', alignItems: 'center' }]}>
            <Text style={[s.bold, { marginRight: 20 }]}>I am:</Text>
            <View style={[s.flexRow, { marginRight: 20 }]}>
              <Checkbox checked={data.iAm === 'the affected entity'} />
              <Text>the affected entity</Text>
            </View>
            <View style={s.flexRow}>
              <Checkbox checked={data.iAm === 'reporting incident affecting other entity'} />
              <Text>reporting incident affecting other entity</Text>
            </View>
          </View>
        </View>

        {/* Row 2: Header */}
        <View style={s.row}>
          <View style={[s.headerCol, { width: '100%' }]}>
            <Text style={s.bold}>Contact Information of the Reporter</Text>
          </View>
        </View>

        {/* Row 3: Name & Role */}
        <View style={s.row}>
          <View style={[s.col, { width: '25%' }]}>
            <Text>Name & Role/Title</Text>
          </View>
          <View style={[s.col, { width: '45%' }]}>
            <Text style={s.inputField}>{data.reporterNameTitle}</Text>
          </View>
          <View style={[s.col, { width: '30%', flexDirection: 'row', justifyContent: 'center' }]}>
            <View style={[s.flexRow, { marginRight: 10 }]}>
              <Checkbox checked={data.reporterRole === 'Individual'} />
              <Text>Individual</Text>
            </View>
            <View style={s.flexRow}>
              <Checkbox checked={data.reporterRole === 'Organization'} />
              <Text>Organization</Text>
            </View>
          </View>
        </View>

        {/* Row 4: Org Name */}
        <View style={s.row}>
          <View style={[s.col, { width: '25%' }]}>
            <Text>Organization name (if any)</Text>
          </View>
          <View style={[s.col, { width: '75%' }]}>
            <Text style={s.inputField}>{data.reporterOrganization}</Text>
          </View>
        </View>

        {/* Row 5: Contact / Email */}
        <View style={s.row}>
          <View style={[s.col, { width: '25%' }]}>
            <Text>Contact No.</Text>
          </View>
          <View style={[s.col, { width: '35%' }]}>
            <Text style={s.inputField}>{data.reporterContactNo}</Text>
          </View>
          <View style={[s.col, { width: '10%' }]}>
            <Text>Email:</Text>
          </View>
          <View style={[s.col, { width: '30%' }]}>
            <Text style={s.inputField}>{data.reporterEmail}</Text>
          </View>
        </View>

        {/* Row 6: Address */}
        <View style={s.row}>
          <View style={[s.col, { width: '25%' }]}>
            <Text>Address:</Text>
          </View>
          <View style={[s.col, { width: '75%' }]}>
            <Text style={[s.inputField, { minHeight: 30 }]}>{data.reporterAddress}</Text>
          </View>
        </View>

        {/* Row 7: Header */}
        <View style={s.row}>
          <View style={[s.headerCol, { width: '100%' }]}>
            <Text style={s.bold}>Basic Incident Details</Text>
          </View>
        </View>

        {/* Row 8: Affected Entity */}
        <View style={s.row}>
          <View style={[s.col, { width: '35%' }]}>
            <Text>Affected entity</Text>
            <Text>(if not same as reporting entity above)</Text>
          </View>
          <View style={[s.col, { width: '65%' }]}>
            <Text style={s.inputField}>{data.affectedEntity}</Text>
          </View>
        </View>

        {/* Row 9: Header Incident Type */}
        <View style={s.row}>
          <View style={[s.col, { width: '100%', alignItems: 'center' }]}>
            <Text style={s.bold}>Incident Type</Text>
          </View>
        </View>

        {/* Row 10: Checkboxes Grid */}
        <View style={s.row}>
          <View style={[s.col, { width: '33.33%' }]}>
            {INCIDENT_TYPES_COL_1.map((item, i) => (
              <View key={i} style={[s.flexRow, s.mb2, { alignItems: 'flex-start' }]}>
                <Checkbox checked={data.incidentTypes.includes(item)} />
                <Text style={{ width: '90%', fontSize: 8 }}>{item}</Text>
              </View>
            ))}
          </View>
          <View style={[s.col, { width: '33.33%' }]}>
            {INCIDENT_TYPES_COL_2.map((item, i) => (
              <View key={i} style={[s.flexRow, s.mb2, { alignItems: 'flex-start' }]}>
                <Checkbox checked={data.incidentTypes.includes(item)} />
                <Text style={{ width: '90%', fontSize: 8 }}>{item}</Text>
              </View>
            ))}
          </View>
          <View style={[s.col, { width: '33.33%' }]}>
            {INCIDENT_TYPES_COL_3.map((item, i) => (
              <View key={i} style={[s.flexRow, s.mb2, { alignItems: 'flex-start' }]}>
                <Checkbox checked={data.incidentTypes.includes(item)} />
                <View style={{ width: '90%', fontSize: 8 }}>
                  <Text>{item}</Text>
                  {item === "Other (Please Specify)" && (
                    <Text style={[s.inputField, { marginTop: 4 }]}>
                      {data.otherIncidentType}
                    </Text>
                  )}
                </View>
              </View>
            ))}
          </View>
        </View>

        {/* Row 11: Criticality */}
        <View style={s.row}>
          <View style={[s.col, { width: '35%' }]}>
            <Text>Is the affected system/network critical to</Text>
            <Text>the organization's mission? (Yes / No).</Text>
            <Text>(Brief details.)</Text>
            <View style={[s.flexRow, { marginTop: 10 }]}>
              <Text>Critical:  </Text>
              <Text style={[s.inputField, { marginLeft: 5 }]}>{data.isCritical}</Text>
            </View>
          </View>
          <View style={[s.col, { width: '65%' }]}>
            <Text style={[s.inputField, { minHeight: 40 }]}>{data.criticalBriefDetails}</Text>
          </View>
        </View>

        {/* Row 12: Basic Information */}
        <View style={s.row}>
          <View style={[s.col, { width: '35%' }]}>
            <Text>Basic Information of Affected System</Text>
            <Text>(Provide information that is readily available.)</Text>
          </View>
          <View style={[s.col, { width: '65%' }]}>
            <View style={[s.flexRow, s.mb2]}>
              <Text style={{ width: 150 }}>Domain/URL:</Text>
              <Text style={[s.inputField, { flex: 1 }]}>{data.affectedSystemDomainUrl}</Text>
            </View>
            <View style={[s.flexRow, s.mb2]}>
              <Text style={{ width: 150 }}>IP Address:</Text>
              <Text style={[s.inputField, { flex: 1 }]}>{data.affectedSystemIp}</Text>
            </View>
            <View style={[s.flexRow, s.mb2]}>
              <Text style={{ width: 150 }}>Operating System:</Text>
              <Text style={[s.inputField, { flex: 1 }]}>{data.affectedSystemOs}</Text>
            </View>
            <View style={[s.flexRow, s.mb2]}>
              <Text style={{ width: 150 }}>Make/ Model/Cloud details:</Text>
              <Text style={[s.inputField, { flex: 1 }]}>{data.affectedSystemMakeModelCloud}</Text>
            </View>
            <View style={[s.flexRow, s.mb2]}>
              <Text style={{ width: 150 }}>Affected Application details (If any):</Text>
              <Text style={[s.inputField, { flex: 1 }]}>{data.affectedSystemAppDetails}</Text>
            </View>
            <View style={[s.flexRow, s.mb2]}>
              <Text style={{ width: 150 }}>Location of affected system (including City, Region & Country):</Text>
              <Text style={[s.inputField, { flex: 1 }]}>{data.affectedSystemLocation}</Text>
            </View>
            <View style={[s.flexRow]}>
              <Text style={{ width: 150 }}>Network and name of ISP:</Text>
              <Text style={[s.inputField, { flex: 1 }]}>{data.affectedSystemIsp}</Text>
            </View>
          </View>
        </View>

        {/* Row 13: Description */}
        <View style={s.row}>
          <View style={[s.col, { width: '35%' }]}>
            <Text>Brief description of Incident:</Text>
            <Text style={[s.inputField, { marginTop: 5, fontFamily: 'Courier', fontSize: 7, minHeight: 60 }]}>
              {data.incidentBriefDescription}
            </Text>
          </View>
          <View style={[s.col, { width: '65%' }]}>
            <View style={{ marginBottom: 15 }}>
              <Text>Occurrence date & time (dd/mm/yyyy hh:mm):</Text>
              <Text style={[s.inputField, { marginTop: 4 }]}>{data.occurrenceDateTime}</Text>
            </View>
            <View>
              <Text>Detection date & time (dd/mm/yyyy hh:mm):</Text>
              <Text style={[s.inputField, { marginTop: 4 }]}>{data.detectionDateTime}</Text>
            </View>
          </View>
        </View>

        {/* Row 14: Footer Note */}
        <View style={s.row}>
          <View style={[s.col, { width: '100%', padding: 6, fontSize: 8 }]}>
            <Text><Text style={s.bold}>Note:</Text> (i) This form provides general guidance in terms of information which could be relevant to the incident.</Text>
            <Text style={{ marginLeft: 22 }}>(ii) It is not mandatory to fill and/or sign this form. Incidents may also be reported by providing relevant information in the communication itself or in any other readable form.</Text>
            <Text style={{ marginLeft: 22 }}>(iii) Reporting entity may, if desired, also provide relevant information other than mentioned in this form.</Text>
          </View>
        </View>
      </View>

      <Text style={[s.bold, { fontSize: 8, marginTop: 4, textAlign: 'center' }]}>
        Mail/Fax incident reports to: CERT-In, Electronics Niketan, CGO Complex, New Delhi 110003 Fax:+91-11-24368546 or email at: incident@cert-in.org.in
      </Text>
    </Page>
  </Document>
);
