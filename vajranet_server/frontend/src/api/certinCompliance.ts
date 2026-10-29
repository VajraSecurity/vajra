import api from './axiosInstance';

export async function saveCertinCompliance(nodeHostIdentifier: string, statusByPointer: Record<string, 'yes' | 'no'>) {
  return api.post('/alerts/certin-compliance', { nodeHostIdentifier, statusByPointer }, { withCredentials: true });
}

export async function getCertinCompliance(nodeHostIdentifier: string) {
  return api.get('/alerts/certin-compliance', {
    withCredentials: true,
    params: { nodeHostIdentifier },
    headers: { Accept: 'application/json' },
  });
}

export async function resetCertinCompliance(nodeHostIdentifier: string) {
  return api.post('/alerts/certin-compliance/reset', { nodeHostIdentifier }, { withCredentials: true });
}

export default { saveCertinCompliance, getCertinCompliance, resetCertinCompliance };
