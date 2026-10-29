/**
 * Assets tab content — mounted as the "Assets" sub-tab of the OpenVAS
 * scanner view inside Vulnerability Scanner (see
 * features/VulnerabilityScanner/index.tsx's OpenVASTab/OPENVAS_TABS, where it
 * sits between that view's own "Scans" and "Settings" tabs). Asset identity
 * resolution is OpenVAS-only, so this deliberately does NOT live as a
 * top-level Network Security tab or a sidebar entry — both were tried and
 * rejected; see App.tsx's /assets redirects for the trail. It reuses the
 * host page's own hero header and tab bars instead of rendering its own.
 *
 * Asset identity resolution ties together the machines the Vajra agent reports
 * and the hosts agentless scanners find, by weighted matching on hardware and
 * network evidence rather than by hashing attributes into an id. This is the
 * fleet-wide list; clicking a row drills into its evidence + timeline in
 * place, via this same tab's own `?assetUuid=` query param — the identical
 * list/detail-within-one-tab convention VulnerabilityScanner/OpenVASScans.tsx
 * already uses for `?taskId=`, rather than a nested route.
 *
 * Gating matches routes/api/assets.ts exactly (checkJwt + requireAdmin =
 * Super Administrator or Group Admin) via Network's own SuperAdminRoute in
 * App.tsx. Unlike other Network sub-tabs there is no on-prem check: assets
 * are built from data already in the fleet DB.
 *
 * Visuals: the list view renders inside the same gradient `PanelHeader`
 * banner OpenVASScans.tsx uses for its own "Scan Tasks" header (title/
 * subtitle/icon on OPENVAS_BRAND.gradient), so this tab reads as part of the
 * same visual family rather than a bespoke Assets look. See ADDENDUM 5 in
 * the asset-identity spec for the restyle brief this implements.
 */
import { useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Fingerprint } from 'lucide-react';
import AssetsList from './AssetsList';
import AssetDetail from './AssetDetail';
import { Panel, PanelHeader, OPENVAS_BRAND } from '../VulnerabilityScanner/scannerUI';
import { AssetsHelpTip } from './ui';
// Shared Tooltip primitive's own Provider, grouping every InfoTip-based badge
// under one open-delay: without it each Tooltip.Root falls back to Base UI's
// library default (600ms), rather than the 200ms tooltip.tsx's own
// TooltipProvider considers right for this app — noticeable given how many
// badges (source/kind/confidence/decision/veto) sit close together here.
import { TooltipProvider } from '@/components/ui/tooltip';

const AssetsTab = () => {
  // Drilled-in asset lives in the URL (?assetUuid=...) rather than plain
  // component state, so a refresh or a shared link lands back on the same
  // detail view — same reasoning as the outer `tab=` param in
  // features/Network/index.tsx and the nessusTab/openvasTab params in
  // VulnerabilityScanner/index.tsx.
  const [searchParams, setSearchParams] = useSearchParams();

  const assetUuid = searchParams.get('assetUuid');

  const openAsset = useCallback((uuid: string) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set('assetUuid', uuid);
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  const closeAsset = useCallback(() => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete('assetUuid');
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  if (assetUuid) {
    return (
      <TooltipProvider>
        <AssetDetail assetUuid={assetUuid} onBack={closeAsset} />
      </TooltipProvider>
    );
  }

  return (
    <TooltipProvider>
      <Panel className="overflow-hidden">
        <PanelHeader
          brand={OPENVAS_BRAND}
          icon={<Fingerprint className="size-5" />}
          title="Assets"
          subtitle="Resolved host identities from authenticated OpenVAS scans."
          actions={<AssetsHelpTip />}
        />
        <AssetsList onOpenAsset={openAsset} />
      </Panel>
    </TooltipProvider>
  );
};

export default AssetsTab;
