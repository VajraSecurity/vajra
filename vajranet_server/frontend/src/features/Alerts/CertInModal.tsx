import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { createPortal } from 'react-dom';
import type { CertinFormDataType } from './CertInTypes';
import { INCIDENT_TYPES_COL_1, INCIDENT_TYPES_COL_2, INCIDENT_TYPES_COL_3 } from './CertInTypes';
import { useConfirm } from '../../context/useConfirm';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  data: CertinFormDataType;
  onChange: React.Dispatch<React.SetStateAction<CertinFormDataType>>;
  onDownload: () => void;
  onSaveDraft?: () => Promise<void>;
  onNewDraft?: () => void;
  onEditDraft?: () => void;
  onDownloadDraft?: () => void;
  hasDraft?: boolean;
  canDownloadDraft?: boolean;
  lastEditedAgoText?: string | null;
  disappearsInText?: string | null;
  historyItems?: Array<{ id: string; actionLabel: string; userLabel: string; storedAt: string; formData: CertinFormDataType }>;
  onRefreshHistory?: () => Promise<void> | void;
  onPreviewHistory?: (formData: CertinFormDataType) => void;
  onDownloadHistory?: (formData: CertinFormDataType) => void;
}

export const CertInModal: React.FC<Props> = ({
  isOpen,
  onClose,
  data,
  onChange,
  onDownload,
  onSaveDraft,
  onNewDraft,
  onEditDraft,
  onDownloadDraft,
  hasDraft = false,
  canDownloadDraft = false,
  lastEditedAgoText = null,
  disappearsInText = null,
  historyItems = [],
  onRefreshHistory,
  onPreviewHistory,
  onDownloadHistory,
}) => {
  const confirm = useConfirm();
  const [errors, setErrors] = useState<string[]>([]);
  const [showSaveDraftPrompt, setShowSaveDraftPrompt] = useState(false);
  const [savingDraft, setSavingDraft] = useState(false);
  const [showHistory, setShowHistory] = useState(false);

  // Refs to every required field, keyed by its `name` attribute (or a
  // synthetic key for the incident-type checkbox group). Used to move
  // keyboard focus to the first invalid field when validation fails.
  const fieldRefs = React.useRef<Record<string, HTMLElement | null>>({});
  const setFieldRef = (key: string) => (el: HTMLElement | null) => {
    fieldRefs.current[key] = el;
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    onChange(prev => ({ ...prev, [name]: value }));
  };

  const handleCancelSaveDraft = () => {
    setShowSaveDraftPrompt(false);
  };

  const handleSaveDraft = async () => {
    if (!onSaveDraft) return;
    setSavingDraft(true);
    try {
      await onSaveDraft();
      setShowSaveDraftPrompt(false);
    } catch (err) {
      console.error('Failed to save draft', err);
    } finally {
      setSavingDraft(false);
    }
  };

  const handleCheckboxChange = (incident: string) => {
    onChange(prev => {
      const isSelected = prev.incidentTypes.includes(incident);
      if (isSelected) {
        const next = { ...prev, incidentTypes: prev.incidentTypes.filter(i => i !== incident) };
        // Clear any previously entered "Other" text when the "Other" checkbox
        // itself is unchecked, so stale text can't linger in state (and print
        // on the generated PDF) after the user removes the selection.
        if (incident === 'Other (Please Specify)') {
          next.otherIncidentType = '';
        }
        return next;
      }
      return { ...prev, incidentTypes: [...prev.incidentTypes, incident] };
    });
  };

  useEffect(() => {
    if (!isOpen) setErrors([]);
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isOpen, onClose]);

  const validateAndDownload = () => {
    const nextErrors: string[] = [];
    // `field` is the key used to look up the ref for this field in
    // fieldRefs, so we can move focus to the first invalid one below.
    const requiredFields = [
      { name: 'I am', field: 'iAm', value: data.iAm },
      { name: 'Reporter role', field: 'reporterRole', value: data.reporterRole },
      { name: 'Name & Title', field: 'reporterNameTitle', value: data.reporterNameTitle },
      { name: 'Contact No', field: 'reporterContactNo', value: data.reporterContactNo },
      { name: 'Email', field: 'reporterEmail', value: data.reporterEmail },
      { name: 'Address', field: 'reporterAddress', value: data.reporterAddress },
      { name: 'Incident Type', field: 'incidentTypes', value: data.incidentTypes.length > 0 ? 'ok' : '' },
      { name: 'Criticality', field: 'isCritical', value: data.isCritical },
      { name: 'Criticality details', field: 'criticalBriefDetails', value: data.criticalBriefDetails },
      { name: 'Domain/URL', field: 'affectedSystemDomainUrl', value: data.affectedSystemDomainUrl },
      { name: 'IP Address', field: 'affectedSystemIp', value: data.affectedSystemIp },
      { name: 'Operating System', field: 'affectedSystemOs', value: data.affectedSystemOs },
      { name: 'Make/Model/Cloud details', field: 'affectedSystemMakeModelCloud', value: data.affectedSystemMakeModelCloud },
      { name: 'Location of affected system (including city, region & country)', field: 'affectedSystemLocation', value: data.affectedSystemLocation },
      { name: 'Network and name of ISP', field: 'affectedSystemIsp', value: data.affectedSystemIsp },
      { name: 'Brief description', field: 'incidentBriefDescription', value: data.incidentBriefDescription },
      { name: 'Occurrence date/time', field: 'occurrenceDateTime', value: data.occurrenceDateTime },
      { name: 'Detection date/time', field: 'detectionDateTime', value: data.detectionDateTime },
    ];

    let firstInvalidField: string | null = null;
    requiredFields.forEach(field => {
      if (!field.value || String(field.value).trim() === '') {
        nextErrors.push(`${field.name} is required.`);
        if (!firstInvalidField) firstInvalidField = field.field;
      }
    });

    if (data.incidentTypes.includes('Other (Please Specify)') && !data.otherIncidentType.trim()) {
      nextErrors.push('Please specify the other incident type.');
      if (!firstInvalidField) firstInvalidField = 'otherIncidentType';
    }

    if (nextErrors.length > 0) {
      setErrors(nextErrors);
      setShowSaveDraftPrompt(true);
      // Move keyboard focus to the first invalid field so the user isn't
      // left to hunt through a 17-field form for what's missing.
      if (firstInvalidField) {
        const el = fieldRefs.current[firstInvalidField];
        el?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        el?.focus();
      }
      return;
    }

    setErrors([]);
    onDownload();
  };

  

  // Ensure hooks are always called in the same order
  // Only return early after hooks are used
  if (!isOpen) return null;

  return createPortal(
    <AnimatePresence>
      <div
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm"
        role="dialog"
        aria-modal="true"
        aria-labelledby="certin-modal-title"
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.95 }}
          className="bg-white rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden"
        >
          {/* Header */}
          <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
            <h2 id="certin-modal-title" className="text-xl font-bold text-slate-800">CERT-In Incident Report Form</h2>
            <button onClick={onClose} aria-label="Close modal" className="rounded-lg text-slate-400 hover:text-slate-600">
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          {(lastEditedAgoText || disappearsInText) && (
            <div className="px-6 py-2 border-b border-slate-200 bg-slate-50 text-xs text-slate-600">
              {lastEditedAgoText ? `Last created/edited ${lastEditedAgoText} ago` : ''}
              {lastEditedAgoText && disappearsInText ? ' • ' : ''}
              {disappearsInText ? `will disappear in ${disappearsInText}` : ''}
            </div>
          )}

          {/* Body */}
          <div className="flex-1 min-h-0 flex bg-white text-sm text-slate-700">
            <aside className="w-44 shrink-0 border-r border-slate-200 bg-slate-50 p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-3">Actions</p>
              <div className="space-y-2">
                <button
                  type="button"
                  onClick={async () => {
                    if (await confirm({
                      title: 'Start a new report?',
                      description: 'Any unsaved changes to the current form will be lost.',
                      confirmLabel: 'Start New',
                      variant: 'danger',
                    })) {
                      onNewDraft?.();
                    }
                  }}
                  className="w-full text-left px-3 py-2 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-700"
                >
                  New
                </button>
                <button
                  type="button"
                  onClick={onEditDraft}
                  disabled={!hasDraft}
                  className="w-full text-left px-3 py-2 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Edit
                </button>
                <button
                  type="button"
                  onClick={onDownloadDraft}
                  disabled={!canDownloadDraft}
                  className="w-full text-left px-3 py-2 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Download
                </button>
                <button
                  type="button"
                  onClick={async () => {
                    setShowHistory((prev) => !prev);
                    if (!showHistory) await onRefreshHistory?.();
                  }}
                  className="w-full text-left px-3 py-2 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-700"
                >
                  History
                </button>
              </div>
            </aside>
            <div className="flex-1 overflow-y-auto p-6 space-y-8">
            {showHistory && (
              <section className="rounded-lg border border-slate-200 bg-slate-50 p-4">
                <h3 className="font-semibold text-slate-800 mb-3">Draft History</h3>
                {historyItems.length === 0 ? (
                  <p className="text-sm text-slate-500">No history available.</p>
                ) : (
                  <div className="space-y-2">
                    {historyItems.map((item) => (
                      <div key={item.id} className="rounded border border-slate-200 bg-white p-3 flex items-center justify-between gap-3">
                        <div>
                          <p className="text-sm font-medium text-slate-800">{item.actionLabel} by {item.userLabel}</p>
                          <p className="text-xs text-slate-500">{new Date(item.storedAt).toLocaleString()}</p>
                        </div>
                        <div className="flex gap-2">
                          <button
                            type="button"
                            onClick={() => onPreviewHistory?.(item.formData)}
                            className="px-2 py-1 text-xs border border-slate-300 rounded hover:bg-slate-50"
                          >
                            Preview
                          </button>
                          <button
                            type="button"
                            onClick={() => onDownloadHistory?.(item.formData)}
                            className="px-2 py-1 text-xs border border-slate-300 rounded hover:bg-slate-50"
                          >
                            Download
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </section>
            )}
            {errors.length > 0 && (
              <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
                <p className="font-semibold mb-2">Please fix the following:</p>
                <ul className="list-disc list-inside space-y-1">
                  {errors.map((error) => (
                    <li key={error}>{error}</li>
                  ))}
                </ul>
              </div>
            )}
            <section>
              <h3 className="font-semibold text-slate-800 mb-4 border-b pb-2">Reporter Information</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block mb-1 font-medium">I am: *</label>
                  <select ref={setFieldRef('iAm')} name="iAm" value={data.iAm} onChange={handleChange} className="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500">
                    <option value="">Select...</option>
                    <option value="the affected entity">The affected entity</option>
                    <option value="reporting incident affecting other entity">Reporting incident affecting other entity</option>
                  </select>
                </div>
                <div>
                  <label className="block mb-1 font-medium">Reporter Role: *</label>
                  <select ref={setFieldRef('reporterRole')} name="reporterRole" value={data.reporterRole} onChange={handleChange} className="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500">
                    <option value="">Select...</option>
                    <option value="Individual">Individual</option>
                    <option value="Organization">Organization</option>
                  </select>
                </div>
                <div>
                  <label className="block mb-1 font-medium">Name & Title: *</label>
                  <input ref={setFieldRef('reporterNameTitle')} type="text" name="reporterNameTitle" value={data.reporterNameTitle} onChange={handleChange} className="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500" />
                </div>
                <div>
                  <label className="block mb-1 font-medium">Organization:</label>
                  <input type="text" name="reporterOrganization" value={data.reporterOrganization} onChange={handleChange} className="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500" />
                </div>
                <div>
                  <label className="block mb-1 font-medium">Contact No: *</label>
                  <input ref={setFieldRef('reporterContactNo')} type="text" name="reporterContactNo" value={data.reporterContactNo} onChange={handleChange} className="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500" />
                </div>
                <div>
                  <label className="block mb-1 font-medium">Email: *</label>
                  <input ref={setFieldRef('reporterEmail')} type="email" name="reporterEmail" value={data.reporterEmail} onChange={handleChange} className="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500" />
                </div>
                <div className="md:col-span-2">
                  <label className="block mb-1 font-medium">Address: *</label>
                  <textarea ref={setFieldRef('reporterAddress')} name="reporterAddress" value={data.reporterAddress} onChange={handleChange} className="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500" rows={2} />
                </div>
              </div>
            </section>

            <section>
              <h3 className="font-semibold text-slate-800 mb-4 border-b pb-2">Incident Details</h3>
              <div className="space-y-4">
                <div>
                  <label className="block mb-1 font-medium">Affected Entity (if different):</label>
                  <input type="text" name="affectedEntity" value={data.affectedEntity} onChange={handleChange} className="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500" />
                </div>
                
                <div>
                  <label className="block mb-2 font-medium">Incident Types: *</label>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
                    {[...INCIDENT_TYPES_COL_1, ...INCIDENT_TYPES_COL_2, ...INCIDENT_TYPES_COL_3].map((type, idx) => (
                      <label key={type} className="flex items-start gap-2">
                        <input
                          ref={idx === 0 ? setFieldRef('incidentTypes') : undefined}
                          type="checkbox"
                          checked={data.incidentTypes.includes(type)}
                          onChange={() => handleCheckboxChange(type)}
                          className="mt-1"
                        />
                        <span>{type}</span>
                      </label>
                    ))}
                  </div>
                  {data.incidentTypes.includes("Other (Please Specify)") && (
                    <input ref={setFieldRef('otherIncidentType')} type="text" name="otherIncidentType" value={data.otherIncidentType} onChange={handleChange} placeholder="Specify other incident type" className="mt-2 w-full p-2 border rounded focus:ring-2 focus:ring-blue-500" />
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block mb-1 font-medium">Is Critical? (Yes/No): *</label>
                    <select ref={setFieldRef('isCritical')} name="isCritical" value={data.isCritical} onChange={handleChange} className="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500">
                      <option value="">Select...</option>
                      <option value="Yes">Yes</option>
                      <option value="No">No</option>
                    </select>
                  </div>
                  <div className="md:col-span-2">
                    <label className="block mb-1 font-medium">Criticality Details: *</label>
                    <textarea ref={setFieldRef('criticalBriefDetails')} name="criticalBriefDetails" value={data.criticalBriefDetails} onChange={handleChange} className="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500" rows={2} />
                  </div>
                </div>
              </div>
            </section>

            <section>
              <h3 className="font-semibold text-slate-800 mb-4 border-b pb-2">System Information</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block mb-1 font-medium">Domain/URL: *</label>
                  <input ref={setFieldRef('affectedSystemDomainUrl')} type="text" name="affectedSystemDomainUrl" value={data.affectedSystemDomainUrl} onChange={handleChange} className="w-full p-2 border rounded" />
                </div>
                <div>
                  <label className="block mb-1 font-medium">IP Address: *</label>
                  <input ref={setFieldRef('affectedSystemIp')} type="text" name="affectedSystemIp" value={data.affectedSystemIp} onChange={handleChange} className="w-full p-2 border rounded" />
                </div>
                <div>
                  <label className="block mb-1 font-medium">OS: *</label>
                  <input ref={setFieldRef('affectedSystemOs')} type="text" name="affectedSystemOs" value={data.affectedSystemOs} onChange={handleChange} className="w-full p-2 border rounded" />
                </div>
                <div>
                  <label className="block mb-1 font-medium">Make/Model/Cloud: *</label>
                  <input ref={setFieldRef('affectedSystemMakeModelCloud')} type="text" name="affectedSystemMakeModelCloud" value={data.affectedSystemMakeModelCloud} onChange={handleChange} className="w-full p-2 border rounded" />
                </div>
                <div>
                  <label className="block mb-1 font-medium">App Details (if any):</label>
                  <input type="text" name="affectedSystemAppDetails" value={data.affectedSystemAppDetails} onChange={handleChange} className="w-full p-2 border rounded" />
                </div>
                <div>
                  <label className="block mb-1 font-medium">Location of affected system (including city, region & country): *</label>
                  <input ref={setFieldRef('affectedSystemLocation')} type="text" name="affectedSystemLocation" value={data.affectedSystemLocation} onChange={handleChange} className="w-full p-2 border rounded" />
                </div>
                <div>
                  <label className="block mb-1 font-medium">ISP: *</label>
                  <input ref={setFieldRef('affectedSystemIsp')} type="text" name="affectedSystemIsp" value={data.affectedSystemIsp} onChange={handleChange} className="w-full p-2 border rounded" />
                </div>
              </div>
            </section>

            <section>
              <h3 className="font-semibold text-slate-800 mb-4 border-b pb-2">Timeline & Description</h3>
              <div className="space-y-4">
                <div>
                  <label className="block mb-1 font-medium">Brief Description: *</label>
                  <textarea ref={setFieldRef('incidentBriefDescription')} name="incidentBriefDescription" value={data.incidentBriefDescription} onChange={handleChange} className="w-full p-2 border rounded font-mono text-xs" rows={4} />
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block mb-1 font-medium">Occurrence Date/Time: *</label>
                    <input ref={setFieldRef('occurrenceDateTime')} type="text" name="occurrenceDateTime" value={data.occurrenceDateTime} onChange={handleChange} placeholder="dd/mm/yyyy hh:mm" className="w-full p-2 border rounded" />
                  </div>
                  <div>
                    <label className="block mb-1 font-medium">Detection Date/Time: *</label>
                    <input ref={setFieldRef('detectionDateTime')} type="text" name="detectionDateTime" value={data.detectionDateTime} onChange={handleChange} placeholder="dd/mm/yyyy hh:mm" className="w-full p-2 border rounded" />
                  </div>
                </div>
              </div>
            </section>
            </div>
          </div>

          {/* Save Draft Prompt (shown when validation fails) */}
          {showSaveDraftPrompt && (
            <div className="px-6 py-3 border-t border-yellow-200 bg-yellow-50 flex items-center justify-between gap-4">
              <div className="text-sm text-slate-800">Form is incomplete. Save this as a draft for 24 hours?</div>
              <div className="flex items-center gap-2">
                <button onClick={handleCancelSaveDraft} className="px-3 py-2 bg-white border border-slate-300 rounded hover:bg-slate-50 text-sm">Continue Editing</button>
                <button onClick={handleSaveDraft} disabled={savingDraft} className="px-3 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 text-sm">
                  {savingDraft ? 'Saving...' : 'Save Draft'}
                </button>
              </div>
            </div>
          )}

          {/* Footer */}
          <div className="px-6 py-4 border-t border-slate-200 bg-slate-50 flex justify-end gap-3">
            <button onClick={onClose} className="px-4 py-2 text-slate-600 bg-white border border-slate-300 rounded hover:bg-slate-50 font-medium">
              Cancel
            </button>
            <button onClick={validateAndDownload} className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 font-medium shadow-sm">
              Generate PDF
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>,
    document.body
  );
};
