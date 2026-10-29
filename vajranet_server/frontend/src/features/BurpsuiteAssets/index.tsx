/**
 * Assets tab content — mounted as the "Assets" sub-tab of the Burp Suite
 * scanner view inside Vulnerability Scanner (see
 * features/VulnerabilityScanner/index.tsx's BurpsuiteTab/BURPSUITE_TABS,
 * where it sits between that view's own "Scans" and "Settings" tabs — same
 * position OpenVAS's own Assets tab occupies among its sibling tabs).
 *
 * A sibling of features/Assets (OpenVAS's identity-resolution assets), kept
 * in its own top-level feature folder rather than nested inside
 * features/Assets — same reason BurpsuiteView.tsx lives alongside the
 * OpenVAS*.tsx files under VulnerabilityScanner/ instead of inside one of
 * them. Burp Suite's asset model is much simpler: no cross-source identity
 * matching, no confidence scoring, no merge concept — just the websites Burp
 * Suite scans have targeted and their scan history.
 *
 * Drilled-in asset lives in this tab's own `?burpAsset=` query param (deliberately
 * distinct from OpenVAS's `?assetUuid=` and from BurpsuiteView.tsx's own
 * `?taskId=`, so all three can coexist in the URL without colliding — the
 * same reasoning VulnerabilityScanner/index.tsx's own nessusTab/openvasTab/
 * burpsuiteTab params already follow for the outer tab state) rather than
 * plain component state, so a refresh or a shared link restores the same view.
 */
import { useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Globe } from 'lucide-react';
import BurpsuiteAssetsList from './BurpsuiteAssetsList';
import BurpsuiteAssetDetail from './BurpsuiteAssetDetail';
import { Panel, PanelHeader, BURP_BRAND } from '../VulnerabilityScanner/scannerUI';
import { BurpsuiteAssetsHelpTip } from './ui';

interface BurpsuiteAssetsTabProps {
  /** Same shared group-scope state VulnerabilityScanner/index.tsx lifts for
   *  OpenVASScans/NessusScans — null means the caller's own default scope. */
  selectedGroupId: string | null;
}

const BurpsuiteAssetsTab = ({ selectedGroupId }: BurpsuiteAssetsTabProps) => {
  const [searchParams, setSearchParams] = useSearchParams();

  const normalizedTarget = searchParams.get('burpAsset');

  const openAsset = useCallback((target: string) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set('burpAsset', target);
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  const closeAsset = useCallback(() => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete('burpAsset');
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  if (normalizedTarget) {
    return <BurpsuiteAssetDetail normalizedTarget={normalizedTarget} onBack={closeAsset} />;
  }

  return (
    <Panel className="overflow-hidden">
      <PanelHeader
        brand={BURP_BRAND}
        icon={<Globe className="size-5" />}
        title="Assets"
        subtitle="Websites targeted by Burp Suite scans."
        actions={<BurpsuiteAssetsHelpTip />}
      />
      <BurpsuiteAssetsList onOpenAsset={openAsset} selectedGroupId={selectedGroupId} />
    </Panel>
  );
};

export default BurpsuiteAssetsTab;
