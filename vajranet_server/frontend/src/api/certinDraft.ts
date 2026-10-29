import api from './axiosInstance';

// `formData` is passed straight through to the backend without inspection
// here; its real shape (CertinFormDataType) lives in the Alerts feature.
export async function saveCertinDraft(formData: unknown, selectedAlertIds?: string[]) {
  return api.post('/alerts/certin-draft', { formData, selectedAlertIds }, { withCredentials: true });
}

export async function getCertinDraft() {
  return api.get('/alerts/certin-draft', { withCredentials: true, headers: { Accept: 'application/json' } });
}
export async function getCertinDraftHistory() {
  return api.get('/alerts/certin-draft/history', { withCredentials: true, headers: { Accept: 'application/json' } });
}

export async function deleteCertinDraft(draftId: number | string) {
  return api.delete(`/alerts/certin-draft/${draftId}`, { withCredentials: true });
}

export async function markCertinDraftDownloaded(draftId: number | string) {
  return api.post(`/alerts/certin-draft/${draftId}/downloaded`, {}, { withCredentials: true });
}

export default { saveCertinDraft, getCertinDraft, getCertinDraftHistory, deleteCertinDraft, markCertinDraftDownloaded };
